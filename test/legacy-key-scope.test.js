'use strict';
/**
 * Scope of the legacy v1 receipt keys, and the type of `leaf`.
 *
 * Rule: a legacy key verifies a receipt only when the leaf is V5 or V6 and the
 * signed preimage timestamp_unix is at or before the key-rotation cutoff. A V7
 * receipt is checked against the current key only. A caller-pinned key is never
 * widened with legacy keys. `leaf` must be a string.
 *
 * tests/test_legacy_key_scope.py holds the same cases for the Python verifier.
 * The legacy seeds are not used: a throwaway key stands in for a legacy key by
 * being appended to the in-memory legacy list for the duration of each case.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const nacl = require('tweetnacl');
const bs58 = require('bs58');

const V = require('../verify_twzrd_receipt.js');

// 2026-08-28T23:59:59Z. Kept as a literal so a change to the constant is a
// deliberate edit in both places.
const CUTOFF = 1787961599;

const TABLE = JSON.parse(fs.readFileSync(path.join(__dirname, '../testdata/v7_edit_cases.json'), 'utf8'));
const V6_FIXTURE = JSON.parse(fs.readFileSync(path.join(__dirname, '../testdata/v6_example.json'), 'utf8')).twzrd_receipt;

// Throwaway keys. NOT production keys.
const STANDIN = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(9));
const STANDIN_PUB = bs58.encode(Buffer.from(STANDIN.publicKey));
const PINNED = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(11));
const PINNED_PUB = bs58.encode(Buffer.from(PINNED.publicKey));

function withStandinLegacyKey(fn) {
  V.LEGACY_RECEIPT_PUBKEYS.push(STANDIN_PUB);
  try { return fn(); } finally { V.LEGACY_RECEIPT_PUBKEYS.pop(); }
}

function sign(pre, kp, envelope) {
  const leaf = V.recomputeLeaf(pre);
  return {
    preimage: structuredClone(pre),
    leaf: '0x' + leaf.toString('hex'),
    signature: bs58.encode(Buffer.from(nacl.sign.detached(leaf, kp.secretKey))),
    signing_alg: 'ed25519',
    ...envelope,
  };
}

function v7Pre() { return structuredClone(TABLE.base.tx); }
function v6Pre(ts) { return { ...structuredClone(V6_FIXTURE.preimage), timestamp_unix: ts }; }
function v5Pre(ts) {
  return { ...v6Pre(ts), domain: 'TWZRD:AO_REPUTATION_RECEIPT_V5', version: 'v5' };
}
const V7_ENV = { version: 'v7', kind: 'twzrd_reputation_receipt_v7' };
const LEGACY_ID = { key_id: V.LEGACY_RECEIPT_SIGNING_KEY_ID };

// name, receipt builder, expected valid. Mirrored in tests/test_legacy_key_scope.py.
const CASES = [
  ['v7 legacy key_id', () => sign(v7Pre(), STANDIN, { ...V7_ENV, ...LEGACY_ID, signing_pubkey: STANDIN_PUB }), false],
  ['v7 legacy key_id, no signing_pubkey', () => sign(v7Pre(), STANDIN, { ...V7_ENV, ...LEGACY_ID }), false],
  ['v7 no key_id, legacy signing_pubkey', () => sign(v7Pre(), STANDIN, { ...V7_ENV, signing_pubkey: STANDIN_PUB }), false],
  ['v7 no key_id, no signing_pubkey', () => sign(v7Pre(), STANDIN, { ...V7_ENV }), false],
  ['v6 legacy key_id at cutoff', () => sign(v6Pre(CUTOFF), STANDIN, { version: 'v6', ...LEGACY_ID, signing_pubkey: STANDIN_PUB }), true],
  ['v6 legacy key_id after cutoff', () => sign(v6Pre(CUTOFF + 1), STANDIN, { version: 'v6', ...LEGACY_ID, signing_pubkey: STANDIN_PUB }), false],
  ['v6 no key_id at cutoff', () => sign(v6Pre(CUTOFF), STANDIN, { version: 'v6' }), true],
  ['v6 no key_id after cutoff', () => sign(v6Pre(CUTOFF + 1), STANDIN, { version: 'v6' }), false],
  ['v6 no key_id after cutoff, legacy signing_pubkey', () => sign(v6Pre(CUTOFF + 1), STANDIN, { version: 'v6', signing_pubkey: STANDIN_PUB }), false],
  ['v5 legacy key_id at cutoff', () => sign(v5Pre(CUTOFF), STANDIN, { version: 'v5', ...LEGACY_ID, signing_pubkey: STANDIN_PUB }), true],
  ['v5 legacy key_id after cutoff', () => sign(v5Pre(CUTOFF + 1), STANDIN, { version: 'v5', ...LEGACY_ID, signing_pubkey: STANDIN_PUB }), false],
  ['v5 no key_id after cutoff', () => sign(v5Pre(CUTOFF + 1), STANDIN, { version: 'v5' }), false],
];

for (const [name, build, expected] of CASES) {
  test(`legacy key scope: ${name} -> ${expected ? 'valid' : 'refused'}`, () => {
    const res = withStandinLegacyKey(() => V.verify(build(), V.CURRENT_RECEIPT_PUBKEY));
    assert.equal(res.valid, expected, JSON.stringify(res.errors));
    if (!expected) assert.equal(res.signature_valid, false);
  });
}

test('legacy key scope: the cutoff constant is 2026-08-28T23:59:59Z', () => {
  assert.equal(V.LEGACY_RECEIPT_KEY_CUTOFF_UNIX, CUTOFF);
});

test('legacy key scope: the published V6 sample still verifies with the default key', () => {
  const res = V.verify(structuredClone(V6_FIXTURE), V.CURRENT_RECEIPT_PUBKEY);
  assert.equal(res.valid, true, JSON.stringify(res.errors));
  assert.equal(res.leaf_version, 'v6');
});

test('legacy key scope: a caller-pinned key is not widened with legacy keys', () => {
  const receipt = sign(v6Pre(CUTOFF), STANDIN, { version: 'v6', ...LEGACY_ID, signing_pubkey: STANDIN_PUB });
  const noEmbedded = sign(v6Pre(CUTOFF), STANDIN, { version: 'v6', ...LEGACY_ID });
  const noKeyId = sign(v6Pre(CUTOFF), STANDIN, { version: 'v6' });
  withStandinLegacyKey(() => {
    for (const r of [receipt, noEmbedded, noKeyId]) {
      const res = V.verify(r, PINNED_PUB);
      assert.equal(res.valid, false);
      assert.equal(res.signature_valid, false);
    }
  });
  // The pinned key itself still verifies what it signed, whatever the key_id says.
  const own = sign(v6Pre(CUTOFF + 1), PINNED, { version: 'v6', ...LEGACY_ID, signing_pubkey: PINNED_PUB });
  assert.equal(V.verify(own, PINNED_PUB).valid, true);
});

for (const [name, build] of [
  ['v7', () => sign(v7Pre(), PINNED, { ...V7_ENV, key_id: V.CURRENT_RECEIPT_SIGNING_KEY_ID, signing_pubkey: PINNED_PUB })],
  ['v6', () => sign(v6Pre(CUTOFF), PINNED, { version: 'v6', key_id: V.CURRENT_RECEIPT_SIGNING_KEY_ID, signing_pubkey: PINNED_PUB })],
]) {
  test(`leaf type: ${name} leaf must be a string`, () => {
    const good = build();
    assert.equal(V.verify(good, PINNED_PUB).valid, true);
    for (const bad of [[good.leaf], { leaf: good.leaf }, 7, true]) {
      const res = V.verify({ ...good, leaf: bad }, PINNED_PUB);
      assert.equal(res.valid, false);
      assert.equal(res.leaf_valid, false);
      assert.ok(res.errors.includes('leaf must be a string'), JSON.stringify(res.errors));
    }
  });
}
