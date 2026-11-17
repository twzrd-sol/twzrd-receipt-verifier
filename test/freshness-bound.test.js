'use strict';
/**
 * `freshness_bound` in the trusted-bits block and the card's FRESHNESS lines
 * state one fact, so they must agree on every receipt.
 *
 * Through 1.4.5 a verified V7 receipt printed `covered by the V7 leaf binding`
 * three times and then `freshness_bound  : false`. The bit is now read from the
 * same function as the card. `trusted_due` and `trusted_allow` stay false
 * everywhere. tests/test_freshness_bound.py holds the Python verifier to the
 * same cases.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('node:child_process');
const nacl = require('tweetnacl');
const bs58 = require('bs58');

const {
  verify,
  recomputeLeaf,
  ED25519_L,
  formatBoundFreshnessCard,
  formatTrustedBits,
  freshnessLeafBound,
  CURRENT_RECEIPT_SIGNING_KEY_ID,
} = require('../verify_twzrd_receipt.js');

const CLI = path.join(__dirname, '..', 'verify_twzrd_receipt.js');
const TABLE = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../testdata/v7_edit_cases.json'), 'utf8'),
);
const FRESHNESS = ['recheck_after_unix', 'staleness_days', 'score_decay_model'];
const LEAF_BOUND_NOTE = 'covered by the V7 leaf binding';
const NOT_BOUND_NOTE = 'present, NOT signature-bound; do not treat as proof';
const BITS = (bound) => [
  'trusted_due      : false',
  'trusted_allow    : false',
  `freshness_bound  : ${bound}`,
].join('\n');

// Deterministic test key (00 01 ... 1f). NOT a production key.
const KP = nacl.sign.keyPair.fromSeed(Uint8Array.from([...Array(32).keys()]));
const TRUSTED = bs58.encode(Buffer.from(KP.publicKey));

function signedV7(pre) {
  const leaf = recomputeLeaf(pre);
  return {
    version: 'v7',
    kind: 'twzrd_reputation_receipt_v7',
    preimage: structuredClone(pre),
    leaf: '0x' + leaf.toString('hex'),
    signature: bs58.encode(Buffer.from(nacl.sign.detached(leaf, KP.secretKey))),
    signing_pubkey: TRUSTED,
    key_id: CURRENT_RECEIPT_SIGNING_KEY_ID,
    signing_alg: 'ed25519',
  };
}

function sPlusL(signatureB58) {
  const sig = Buffer.from(bs58.decode(signatureB58));
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]);
  s += ED25519_L;
  for (let i = 32; i < 64; i++) {
    sig[i] = Number(s & 0xffn);
    s >>= 8n;
  }
  return bs58.encode(sig);
}

function applyEdits(receipt, edits) {
  for (const edit of edits) {
    if (edit.op === 's_plus_l') {
      receipt.signature = sPlusL(receipt.signature);
      continue;
    }
    let obj = receipt;
    for (const key of edit.path.slice(0, -1)) obj = obj[key];
    const last = edit.path[edit.path.length - 1];
    if (edit.op === 'set') obj[last] = edit.value;
    else if (edit.op === 'delete') delete obj[last];
    else throw new Error(`unknown edit op ${edit.op}`);
  }
  return receipt;
}

function loadV6Example() {
  const env = JSON.parse(fs.readFileSync(path.join(__dirname, '../testdata/v6_example.json'), 'utf8'));
  return structuredClone(env.twzrd_receipt || env);
}

/** What the card says about freshness: 'bound', 'unbound', or null when it lists no freshness field. */
function cardFreshness(card) {
  const lines = card.split('\n').filter((line) => line.startsWith('FRESHNESS '));
  if (lines.length === 0) return null;
  const bound = lines.filter((line) => line.endsWith(LEAF_BOUND_NOTE)).length;
  assert.ok(bound === 0 || bound === lines.length, `FRESHNESS lines disagree with each other:\n${card}`);
  return bound > 0 ? 'bound' : 'unbound';
}

function runCli(receipt, extra = []) {
  const file = path.join(os.tmpdir(), `twzrd-freshness-bound-${process.pid}-${Math.random().toString(36).slice(2)}.json`);
  fs.writeFileSync(file, JSON.stringify(receipt));
  try {
    return spawnSync(process.execPath, [CLI, file, '--pubkey', TRUSTED, ...extra], { encoding: 'utf8' });
  } finally {
    fs.unlinkSync(file);
  }
}

test('a verified V7 receipt reads freshness_bound true, under FRESHNESS lines that say the same', () => {
  for (const [name, pre] of Object.entries(TABLE.base)) {
    const receipt = signedV7(pre);
    const res = verify(receipt, TRUSTED);
    assert.equal(res.valid, true, name);
    assert.equal(res.freshness_unauthenticated, false, name);
    assert.equal(freshnessLeafBound(res), true, name);
    assert.equal(formatTrustedBits(receipt, res), BITS(true), name);
    const card = formatBoundFreshnessCard(receipt, res);
    for (const field of FRESHNESS) assert.ok(card.includes(`FRESHNESS ${field}   ${LEAF_BOUND_NOTE}`), `${name} ${field}`);
    assert.equal(cardFreshness(card), 'bound', name);
  }
});

test('every V7 edit case: the bit follows the verdict and never disagrees with the card', () => {
  assert.ok(TABLE.cases.length >= 30);
  let bound = 0;
  for (const c of TABLE.cases) {
    const receipt = applyEdits(signedV7(TABLE.base[c.base]), c.edits);
    const res = verify(receipt, TRUSTED);
    const bits = formatTrustedBits(receipt, res);
    const card = formatBoundFreshnessCard(receipt, res);
    // An edited receipt is bound exactly when it still verifies.
    assert.equal(bits, BITS(res.valid === true), c.name);
    const said = cardFreshness(card);
    if (said !== null) assert.equal(said, res.valid === true ? 'bound' : 'unbound', c.name);
    if (res.valid !== true) assert.ok(!card.includes(LEAF_BOUND_NOTE), c.name);
    if (res.valid === true) bound += 1;
  }
  // The table is mostly refusals; make sure the loop saw them.
  assert.ok(bound < TABLE.cases.length);
});

test('a verified V6 receipt stays false, whatever its JSON claims', () => {
  const receipt = loadV6Example();
  receipt.freshness_bound = true;
  receipt.preimage.freshness_bound = true;
  receipt.preimage.trusted_allow = true;
  receipt.preimage.trusted_due = true;
  const res = verify(receipt, receipt.signing_pubkey);
  assert.equal(res.valid, true);
  assert.equal(freshnessLeafBound(res), false);
  assert.equal(formatTrustedBits(receipt, res), BITS(false));
  assert.equal(cardFreshness(formatBoundFreshnessCard(receipt, res)), 'unbound');
});

test('a V7 domain written onto a V6 signature stays false', () => {
  const receipt = loadV6Example();
  receipt.preimage = { ...receipt.preimage, domain: 'TWZRD:AO_REPUTATION_RECEIPT_V7', version: 'v7' };
  receipt.kind = 'twzrd_reputation_receipt_v7';
  receipt.version = 'v7';
  const res = verify(receipt, receipt.signing_pubkey);
  assert.equal(res.valid, false);
  assert.equal(formatTrustedBits(receipt, res), BITS(false));
  assert.ok(!formatBoundFreshnessCard(receipt, res).includes(LEAF_BOUND_NOTE));
});

test('the bit is read from the verification result, and only a complete one', () => {
  const v7 = signedV7(TABLE.base.tx);
  for (const res of [
    undefined,
    null,
    {},
    { valid: true },
    { valid: true, freshness_unauthenticated: true },
    { valid: true, freshness_unauthenticated: undefined },
    { valid: true, freshness_unauthenticated: null },
    { valid: true, freshness_unauthenticated: 0 },
    { valid: false, freshness_unauthenticated: false },
    { freshness_unauthenticated: false },
  ]) {
    assert.equal(freshnessLeafBound(res), false, JSON.stringify(res));
    assert.equal(formatTrustedBits(v7, res), BITS(false), JSON.stringify(res));
  }
  // The other two lines never move, whatever a result object carries.
  const loud = { valid: true, freshness_unauthenticated: false, trusted_allow: true, trusted_due: true };
  assert.equal(formatTrustedBits(v7, loud), BITS(true));
});

test('CLI: verified V7 prints freshness_bound true once, and the other two bits false', () => {
  const proc = runCli(signedV7(TABLE.base.tx), ['--self-test']);
  assert.equal(proc.status, 0, proc.stdout + proc.stderr);
  assert.match(proc.stdout, /RESULT           : VALID/);
  assert.equal(proc.stdout.split(LEAF_BOUND_NOTE).length - 1, 3);
  assert.equal(proc.stdout.split('freshness_bound  : true').length - 1, 1);
  assert.doesNotMatch(proc.stdout, /freshness_bound  : false/);
  assert.match(proc.stdout, /trusted_due      : false/);
  assert.match(proc.stdout, /trusted_allow    : false/);
  assert.doesNotMatch(proc.stdout, /trusted_(due|allow)\s*:\s*true/);
});

test('CLI: an edited V7 receipt prints INVALID, freshness_bound false and no leaf-binding claim', () => {
  const receipt = signedV7(TABLE.base.tx);
  receipt.preimage.score = (receipt.preimage.score || 0) + 1;
  const proc = runCli(receipt);
  assert.equal(proc.status, 1, proc.stdout + proc.stderr);
  assert.match(proc.stdout, /RESULT           : INVALID/);
  assert.match(proc.stdout, /freshness_bound  : false/);
  assert.doesNotMatch(proc.stdout, /freshness_bound  : true/);
  assert.ok(!proc.stdout.includes(LEAF_BOUND_NOTE));
  assert.ok(proc.stdout.includes(`FRESHNESS recheck_after_unix   ${NOT_BOUND_NOTE}`));
});

test('CLI: a V7 receipt refused for age prints freshness_bound false', () => {
  const proc = runCli(signedV7(TABLE.base.tx), ['--max-age', '1']);
  assert.equal(proc.status, 1, proc.stdout + proc.stderr);
  assert.match(proc.stdout, /RESULT           : INVALID/);
  assert.match(proc.stdout, /freshness_bound  : false/);
  assert.ok(!proc.stdout.includes(LEAF_BOUND_NOTE));
});
