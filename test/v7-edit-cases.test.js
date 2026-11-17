'use strict';
/**
 * Edits to a signed V7 receipt: every case in testdata/v7_edit_cases.json.
 *
 * The Python verifier (tests/test_v7_edit_cases.py), the issuer's
 * verify_receipt and the SDK read the same table, so the four verifiers reach
 * the same verdict on the same edit.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const nacl = require('tweetnacl');
const bs58 = require('bs58');

const {
  verify,
  recomputeLeaf,
  ed25519Verify,
  ED25519_L,
  formatBoundFreshnessCard,
  CURRENT_RECEIPT_SIGNING_KEY_ID,
} = require('../verify_twzrd_receipt.js');

const TABLE = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../testdata/v7_edit_cases.json'), 'utf8'),
);

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

// S + L passes the group equation tweetnacl checks, so only an explicit S < L
// check refuses it. S < L < 2^253, so S + L still fits in 32 bytes.
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

test('edit table bases recompute to the recorded leaves', () => {
  for (const [name, pre] of Object.entries(TABLE.base)) {
    assert.equal('0x' + recomputeLeaf(pre).toString('hex'), TABLE.base_leaf[name], name);
  }
});

for (const c of TABLE.cases) {
  test(`V7 edit: ${c.name}`, () => {
    const receipt = applyEdits(signedV7(TABLE.base[c.base]), c.edits);
    const res = verify(receipt, TRUSTED);
    if (c.expect === 'valid') {
      assert.equal(res.valid, true, JSON.stringify(res.errors));
      return;
    }
    assert.equal(res.valid, false);
    assert.ok(res.errors.some((msg) => msg.includes(c.error)), JSON.stringify(res.errors));
  });
}

test('ed25519Verify refuses S + L that tweetnacl alone accepts', () => {
  const receipt = signedV7(TABLE.base.tx);
  const leaf = recomputeLeaf(receipt.preimage);
  const forged = Buffer.from(bs58.decode(sPlusL(receipt.signature)));
  assert.equal(nacl.sign.detached.verify(new Uint8Array(leaf), new Uint8Array(forged), KP.publicKey), true);
  assert.equal(ed25519Verify(leaf, forged, Buffer.from(KP.publicKey)), false);
  assert.equal(ed25519Verify(leaf, Buffer.from(bs58.decode(receipt.signature)), Buffer.from(KP.publicKey)), true);
});

test('ed25519Verify keeps tweetnacl size errors (the S check runs after it)', () => {
  const receipt = signedV7(TABLE.base.tx);
  const leaf = recomputeLeaf(receipt.preimage);
  const sig = Buffer.from(bs58.decode(receipt.signature));
  assert.throws(() => ed25519Verify(leaf, sig, Buffer.alloc(31)), /bad public key size/);
  assert.throws(() => ed25519Verify(leaf, sig.subarray(0, 63), Buffer.from(KP.publicKey)), /bad signature size/);
  // A non-canonical S under a wrong-size key still reports the size, as 1.4.4 did.
  const forged = Buffer.from(bs58.decode(sPlusL(receipt.signature)));
  assert.throws(() => ed25519Verify(leaf, forged, Buffer.alloc(31)), /bad public key size/);
});

test('card says the leaf covers only the last 32 bytes of a long settlement_tx', () => {
  const long = signedV7(TABLE.base.tx);
  const longCard = formatBoundFreshnessCard(long, verify(long, TRUSTED));
  assert.ok(longCard.includes('BOUND     settlement_tx   last 32 bytes covered by Ed25519 over the signed payload'), longCard);

  const tx = 'short-settlement-ref';
  const anchor = Buffer.concat([Buffer.alloc(32 - tx.length), Buffer.from(tx, 'utf8')]).toString('hex');
  const short = signedV7({ ...TABLE.base.tx, settlement_tx: tx, settlement_anchor: anchor });
  const res = verify(short, TRUSTED);
  assert.equal(res.valid, true, JSON.stringify(res.errors));
  const shortCard = formatBoundFreshnessCard(short, res);
  assert.ok(shortCard.includes('BOUND     settlement_tx   covered by Ed25519 over the signed payload'), shortCard);
  assert.ok(!shortCard.includes('last 32 bytes'), shortCard);
});
