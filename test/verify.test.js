'use strict';
// Tests for the standalone TWZRD AO-Receipt V5 verifier (verify_twzrd_receipt.js),
// the npm twin of the PyPI twzrd-receipt-verifier. As the independent, zero-trust
// verifier external parties run, it MUST fail closed on forged / tampered /
// unsigned receipts and accept a genuinely-signed one. It reimplements the leaf
// layout + Ed25519 verify from scratch (tweetnacl / js-sha3 / bs58, no TWZRD
// code), so it can silently diverge from the canonical signer AND from the Python
// verifier -- the EXPECTED_LEAF_HEX assertion below pins byte-for-byte agreement.

const test = require('node:test');
const assert = require('node:assert/strict');
const nacl = require('tweetnacl');
const bs58 = require('bs58');

const { verify, recomputeLeaf } = require('../verify_twzrd_receipt.js');

// Deterministic test key (seed 00 01 ... 1f). NOT a production key.
const SEED = Uint8Array.from([...Array(32).keys()]);
const KP = nacl.sign.keyPair.fromSeed(SEED);
const TRUSTED_PUBKEY = bs58.encode(Buffer.from(KP.publicKey));

const BASE_PREIMAGE = {
  domain: 'TWZRD:GLOBAL_V5',
  agent_id: 'agent_test01',
  score: 77,
  confidence_bps: 8000,
  timestamp_unix: 1750000000,
  payer: '11111111111111111111111111111112',
  settlement_tx: null,
};

// Cross-language lock: this is the leaf the PYTHON verifier computes for the same
// preimage (verified out-of-band). If either verifier's byte layout / domain /
// hash drifts, this fails -- catching JS<->Python divergence that would make
// external verification depend on which implementation a counterparty happened
// to run.
const EXPECTED_LEAF_HEX =
  '0x615673a77b0caea5f58b24441b2ce0121091532bf050e49717f46ceabe4077c0';

function signedReceipt(preimage) {
  const leaf = recomputeLeaf(preimage);
  const sig = nacl.sign.detached(new Uint8Array(leaf), KP.secretKey);
  return {
    preimage: { ...preimage },
    leaf: '0x' + leaf.toString('hex'),
    signature: bs58.encode(Buffer.from(sig)),
    signing_pubkey: TRUSTED_PUBKEY,
  };
}

test('leaf layout matches the Python verifier byte-for-byte', () => {
  const leaf = '0x' + recomputeLeaf(BASE_PREIMAGE).toString('hex');
  assert.equal(leaf, EXPECTED_LEAF_HEX);
});

test('genuine receipt verifies', () => {
  const res = verify(signedReceipt(BASE_PREIMAGE), TRUSTED_PUBKEY);
  assert.equal(res.leaf_valid, true, JSON.stringify(res.errors));
  assert.equal(res.signature_valid, true, JSON.stringify(res.errors));
  assert.equal(res.valid, true);
});

test('unsigned receipt is rejected', () => {
  const rec = signedReceipt(BASE_PREIMAGE);
  delete rec.signature;
  const res = verify(rec, TRUSTED_PUBKEY);
  assert.equal(res.signature_valid, false);
  assert.ok(res.errors.some((e) => /unsigned|missing signature/.test(e)));
});

test('tampered score breaks the leaf', () => {
  const rec = signedReceipt(BASE_PREIMAGE);
  rec.preimage.score = 999;
  const res = verify(rec, TRUSTED_PUBKEY);
  assert.equal(res.leaf_valid, false);
  assert.equal(res.signature_valid, false);
});

test('tampered payer breaks the leaf', () => {
  const rec = signedReceipt(BASE_PREIMAGE);
  rec.preimage.payer = 'So11111111111111111111111111111111111111112';
  const res = verify(rec, TRUSTED_PUBKEY);
  assert.equal(res.leaf_valid, false);
  assert.equal(res.signature_valid, false);
});

test('forged signature (different key) is rejected', () => {
  const rec = signedReceipt(BASE_PREIMAGE);
  const attacker = nacl.sign.keyPair.fromSeed(
    Uint8Array.from([1, ...Array(31).keys()]),
  );
  const leaf = recomputeLeaf(rec.preimage);
  rec.signature = bs58.encode(
    Buffer.from(nacl.sign.detached(new Uint8Array(leaf), attacker.secretKey)),
  );
  const res = verify(rec, TRUSTED_PUBKEY);
  assert.equal(res.leaf_valid, true); // leaf itself untouched
  assert.equal(res.signature_valid, false);
});

test('wrong trusted key is rejected (embedded signing_pubkey mismatch)', () => {
  const rec = signedReceipt(BASE_PREIMAGE);
  const other = bs58.encode(
    Buffer.from(
      nacl.sign.keyPair.fromSeed(Uint8Array.from([2, ...Array(31).keys()]))
        .publicKey,
    ),
  );
  const res = verify(rec, other);
  assert.equal(res.signature_valid, false);
  assert.ok(res.errors.some((e) => /!= trusted published key/.test(e)));
});

// ── V6: reputation_* fields bound into the leaf ─────────────────────
// Canonical vector shared with the issuer (RECEIPT_V6_LEAF_SPEC.md), the Rust
// crate, the TS SDK, and the Python verifier. All must reproduce this leaf or a
// real V6 receipt from intel.twzrd.xyz cannot be verified.
const CANON_V6_PREIMAGE = {
  domain: 'TWZRD:AO_REPUTATION_RECEIPT_V6',
  agent_id: '11111111111111111111111111111111',
  score: 72,
  confidence_bps: 8000,
  timestamp_unix: 1748736000,
  payer: '11111111111111111111111111111111',
  settlement_tx: 'EXAMPLE-sample-receipt-no-real-settlement-tx-0001',
  reputation_score: 4242,
  reputation_confidence_bps: 7500,
  reputation_score_version: 'intel_renorm_v1',
  reputation_feature_window_start_unix: 1748000000,
  reputation_data_quality: 'high',
};
const CANON_V6_LEAF =
  '0x4c82649d2be393b1fca2da7c5d4c7afebb189ad3f0b93b620ce2e552fe5ce558';

test('V6 canonical leaf matches issuer / Rust / Python byte-for-byte', () => {
  const leaf = '0x' + recomputeLeaf(CANON_V6_PREIMAGE).toString('hex');
  assert.equal(leaf, CANON_V6_LEAF);
});

test('V6 genuine receipt verifies', () => {
  const res = verify(signedReceipt(CANON_V6_PREIMAGE), TRUSTED_PUBKEY);
  assert.equal(res.leaf_valid, true, JSON.stringify(res.errors));
  assert.equal(res.signature_valid, true, JSON.stringify(res.errors));
});

test('V6 forged reputation field breaks the leaf (the bug V6 closes)', () => {
  const rec = signedReceipt(CANON_V6_PREIMAGE);
  rec.preimage.reputation_score = 9999; // was 4242
  rec.preimage.reputation_data_quality = 'PWNED';
  const res = verify(rec, TRUSTED_PUBKEY);
  assert.equal(res.leaf_valid, false);
  assert.equal(res.signature_valid, false);
});
