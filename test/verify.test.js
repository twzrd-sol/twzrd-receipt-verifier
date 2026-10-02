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

const {
  verify, recomputeLeaf,
  verifyCnft, isCnftReceipt, resolveWallet, DEFAULT_CNFT_PUBKEY,
  KNOWN_RECEIPT_DOMAINS, REPUTATION_V5_DOMAIN,
  CURRENT_RECEIPT_SIGNING_KEY_ID,
  DEFAULT_MAX_FUTURE_SKEW_SECONDS, MAX_AGENT_ID_UTF8, MAX_PROOF_DEPTH,
} = require('../verify_twzrd_receipt.js');

// Deterministic test key (seed 00 01 ... 1f). NOT a production key.
const SEED = Uint8Array.from([...Array(32).keys()]);
const KP = nacl.sign.keyPair.fromSeed(SEED);
const TRUSTED_PUBKEY = bs58.encode(Buffer.from(KP.publicKey));

// Canonical AO reputation domain (strict allowlist). Pre-fortify tests used
// TWZRD:GLOBAL_V5 which only worked via substring remapping; that path is gone.
const BASE_PREIMAGE = {
  domain: REPUTATION_V5_DOMAIN,
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
    key_id: CURRENT_RECEIPT_SIGNING_KEY_ID,
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
  assert.ok(res.errors.some((e) => /is not trusted/.test(e)));
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
  // Canonical vector has no freshness triple, so empty is honest.
  assert.deepEqual(res.unauthenticated_fields, []);
});

test('V6 freshness triple is unauthenticated (JSON-only, not in the leaf)', () => {
  const pre = {
    ...CANON_V6_PREIMAGE,
    recheck_after_unix: CANON_V6_PREIMAGE.timestamp_unix + 3 * 86400,
    staleness_days: 3,
    score_decay_model: 'step:<=7d=1.0,<=30d=0.8,<=90d=0.5,>90d=0.25',
  };
  const res = verify(signedReceipt(pre), TRUSTED_PUBKEY);
  assert.equal(res.leaf_valid, true, JSON.stringify(res.errors));
  assert.deepEqual(new Set(res.unauthenticated_fields), new Set([
    'recheck_after_unix', 'staleness_days', 'score_decay_model',
  ]));
});

test('V6 forged reputation field breaks the leaf (the bug V6 closes)', () => {
  const rec = signedReceipt(CANON_V6_PREIMAGE);
  rec.preimage.reputation_score = 9999; // was 4242
  rec.preimage.reputation_data_quality = 'PWNED';
  const res = verify(rec, TRUSTED_PUBKEY);
  assert.equal(res.leaf_valid, false);
  assert.equal(res.signature_valid, false);
});

// ── cNFT (Bubblegum anchor) receipts ────────────────────────────────────
// The genesis compressed-NFT receipts are a DIFFERENT scheme from the keccak-leaf
// trust-API receipts above: Ed25519 signed directly over a compact-JSON payload
// (no leaf), hex signature, signed by the airship authority. `wallet` is the first
// signed field but lives in the <wallet>.json URL, not the anchor block.

// A valid 32-byte base58 wallet (the System program id reused as a stand-in).
const CNFT_WALLET = '11111111111111111111111111111112';
const CNFT_FIELDS = {
  tier_at_mint: 'Gold', score_at_mint: 123,
  verified_tx: 'TESTtxSignatureNotReal', behavior_proof: 'deadbeef', minted_at: 1750000000,
};

// Mirror airship.ts payload(): compact JSON, EXACT key order, then Ed25519 sign.
function signedCnft(wallet, fields, kp = KP) {
  const payload = JSON.stringify({
    wallet,
    tier_at_mint: fields.tier_at_mint,
    score_at_mint: fields.score_at_mint,
    verified_tx: fields.verified_tx,
    behavior_proof: fields.behavior_proof,
    minted_at: fields.minted_at,
  });
  const sig = nacl.sign.detached(Uint8Array.from(Buffer.from(payload, 'utf8')), kp.secretKey);
  return {
    anchor: {
      ...fields,
      signature: Buffer.from(sig).toString('hex'),
      verify_pubkey: bs58.encode(Buffer.from(kp.publicKey)),
    },
  };
}

test('cNFT receipt is detected (and trust-API receipts are not)', () => {
  assert.equal(isCnftReceipt(signedCnft(CNFT_WALLET, CNFT_FIELDS)), true);
  assert.equal(isCnftReceipt(signedReceipt(BASE_PREIMAGE)), false);
});

test('cNFT genuine anchor verifies', () => {
  const res = verifyCnft(signedCnft(CNFT_WALLET, CNFT_FIELDS), TRUSTED_PUBKEY, CNFT_WALLET);
  assert.equal(res.signature_valid, true, JSON.stringify(res.errors));
  assert.equal(res.valid, true);
});

test('cNFT tampered score is rejected', () => {
  const rec = signedCnft(CNFT_WALLET, CNFT_FIELDS);
  rec.anchor.score_at_mint = 999;
  const res = verifyCnft(rec, TRUSTED_PUBKEY, CNFT_WALLET);
  assert.equal(res.signature_valid, false);
  assert.equal(res.valid, false);
});

test('cNFT wrong wallet is rejected (wallet is bound into the signature)', () => {
  const rec = signedCnft(CNFT_WALLET, CNFT_FIELDS);
  const res = verifyCnft(rec, TRUSTED_PUBKEY, 'So11111111111111111111111111111111111111112');
  assert.equal(res.signature_valid, false);
});

test('cNFT missing wallet errors clearly (not a silent pass)', () => {
  const res = verifyCnft(signedCnft(CNFT_WALLET, CNFT_FIELDS), TRUSTED_PUBKEY, undefined);
  assert.equal(res.valid, undefined);
  assert.ok(res.errors.some((e) => /wallet unknown/.test(e)));
});

test('cNFT wrong key is rejected (embedded verify_pubkey mismatch)', () => {
  const rec = signedCnft(CNFT_WALLET, CNFT_FIELDS);
  const other = bs58.encode(Buffer.from(
    nacl.sign.keyPair.fromSeed(Uint8Array.from([7, ...Array(31).keys()])).publicKey));
  const res = verifyCnft(rec, other, CNFT_WALLET);
  assert.equal(res.signature_valid, false);
  assert.ok(res.errors.some((e) => /verify_pubkey .* != trusted key/.test(e)));
});

test('cNFT forged signature (different key) is rejected', () => {
  const attacker = nacl.sign.keyPair.fromSeed(Uint8Array.from([9, ...Array(31).keys()]));
  const rec = signedCnft(CNFT_WALLET, CNFT_FIELDS, attacker);
  // Hardest case: the anchor CLAIMS the trusted key, but the signature is the
  // attacker's — so it slips past the embedded-key check and must fail on the crypto.
  rec.anchor.verify_pubkey = TRUSTED_PUBKEY;
  const res = verifyCnft(rec, TRUSTED_PUBKEY, CNFT_WALLET);
  assert.equal(res.signature_valid, false);
  assert.equal(res.valid, false);
});

test('resolveWallet infers the wallet from a <wallet>.json filename', () => {
  const r = resolveWallet({ receiptPath: `/tmp/${CNFT_WALLET}.json` });
  assert.equal(r.wallet, CNFT_WALLET);
  assert.equal(r.src, 'filename');
});

test('resolveWallet rejects a non-pubkey filename stem', () => {
  const r = resolveWallet({ receiptPath: '/tmp/not-a-wallet.json' });
  assert.equal(r.wallet, undefined);
  assert.equal(r.src, 'none');
});

// REAL production fixture — the genesis cNFT for wallet zoz7neLH..., as served at
// https://twzrd.xyz/r/<wallet>.json and bound on-chain in tree 8QFdTqBk... with
// verified creator 2ELSDx. Locks the verifier to the actual signer's output
// (the cNFT analogue of EXPECTED_LEAF_HEX). If this fails, the published verifier
// can no longer verify the 95k real receipts.
const REAL_WALLET = 'zoz7neLHXoaLwNBuckSqNqaMsacpqJsphtFuNNpQyt3';
const REAL_ANCHOR = {
  anchor: {
    tier_at_mint: 'Platinum',
    score_at_mint: 255,
    verified_tx: '4StuBXZr4LBWVGtTdWKdFFpM9NFWSzofmChT7QjrBYHSQZ81bEbW9h7EyyPh63N5EsMHAeXSRFCiKvSMiEg2QNUn',
    behavior_proof: '2c5074ccfabd7360ff8bca0607483eadcb0e8b74e6bfe7b3de864b2614d64d46',
    minted_at: 1782415336,
    signature: 'ec3bfe6f9e65e0ee69fea39ea35db1e7d5a30930cd6357576cf4b2221b626c7a228cbd019d98ca120728c64b2678fa5bb90817933d1c9cd6c0db3a526e258f07',
    verify_pubkey: '2ELSDxLkb7dYrN6EUG69tNtULAq4Fo7WPvXyrZPmuFif',
  },
};

test('REAL genesis cNFT verifies against the built-in 2ELSDx key', () => {
  assert.equal(DEFAULT_CNFT_PUBKEY, '2ELSDxLkb7dYrN6EUG69tNtULAq4Fo7WPvXyrZPmuFif');
  const res = verifyCnft(REAL_ANCHOR, DEFAULT_CNFT_PUBKEY, REAL_WALLET);
  assert.equal(res.signature_valid, true, JSON.stringify(res.errors));
  assert.equal(res.valid, true);
});

test('REAL genesis cNFT fails if any signed field is altered', () => {
  const rec = JSON.parse(JSON.stringify(REAL_ANCHOR));
  rec.anchor.tier_at_mint = 'Platinum '; // trailing space — one byte
  const res = verifyCnft(rec, DEFAULT_CNFT_PUBKEY, REAL_WALLET);
  assert.equal(res.valid, false);
});

// ── Python parity fortify (domain allowlist, lengths, max-age / future skew) ──

test('KNOWN_RECEIPT_DOMAINS matches Python allowlist', () => {
  assert.ok(KNOWN_RECEIPT_DOMAINS.has('TWZRD:AO_REPUTATION_RECEIPT_V5'));
  assert.ok(KNOWN_RECEIPT_DOMAINS.has('TWZRD:AO_REPUTATION_RECEIPT_V6'));
  assert.ok(KNOWN_RECEIPT_DOMAINS.has('TWZRD:AO_REPUTATION_RECEIPT_V7'));
  assert.ok(KNOWN_RECEIPT_DOMAINS.has('TWZRD:AO_ATTENTION_RECEIPT_V5'));
  assert.ok(KNOWN_RECEIPT_DOMAINS.has('TWZRD:AO_ATTENTION_RECEIPT_V6'));
  assert.equal(KNOWN_RECEIPT_DOMAINS.size, 5);
  assert.equal(DEFAULT_MAX_FUTURE_SKEW_SECONDS, 300);
});

test('non-canonical domain is rejected (no substring spoof)', () => {
  const pre = { ...BASE_PREIMAGE, domain: 'TWZRD:AO_REPUTATION_RECEIPT_V5_HAHA' };
  assert.throws(() => recomputeLeaf(pre), /non-canonical domain/);
  const rec = signedReceipt(BASE_PREIMAGE);
  rec.preimage = { ...rec.preimage, domain: 'TWZRD:AO_REPUTATION_RECEIPT_V5_HAHA' };
  const res = verify(rec, TRUSTED_PUBKEY);
  assert.equal(res.valid, false);
  assert.ok(res.errors.some((e) => /non-canonical domain/.test(e)));
});

test('GLOBAL_V5 legacy domain string is rejected under strict allowlist', () => {
  const pre = { ...BASE_PREIMAGE, domain: 'TWZRD:GLOBAL_V5' };
  assert.throws(() => recomputeLeaf(pre), /non-canonical domain/);
});

test('malformed signature length is rejected', () => {
  const rec = signedReceipt(BASE_PREIMAGE);
  // 32-byte base58 payload is a valid encoding but wrong length for Ed25519 sig.
  rec.signature = bs58.encode(Buffer.alloc(32));
  const res = verify(rec, TRUSTED_PUBKEY);
  assert.equal(res.valid, false);
  assert.ok(res.errors.some((e) => /signature length/.test(e)));
});

test('malformed leaf hex is rejected', () => {
  const rec = signedReceipt(BASE_PREIMAGE);
  rec.leaf = '0xdead';
  const res = verify(rec, TRUSTED_PUBKEY);
  assert.equal(res.valid, false);
  assert.ok(res.errors.some((e) => /64 hex/.test(e)));
});

test('oversized agent_id is rejected', () => {
  const pre = { ...BASE_PREIMAGE, agent_id: 'x'.repeat(MAX_AGENT_ID_UTF8 + 1) };
  assert.throws(() => recomputeLeaf(pre), /MAX_AGENT_ID_UTF8/);
});

test('max_age rejects expired receipts', () => {
  const pre = {
    ...BASE_PREIMAGE,
    timestamp_unix: Math.floor(Date.now() / 1000) - 100,
  };
  const rec = signedReceipt(pre);
  const res = verify(rec, TRUSTED_PUBKEY, { maxAgeSeconds: 10 });
  assert.equal(res.valid, false);
  assert.ok(res.errors.some((e) => /too old/.test(e)));
});

test('max_age rejects far-future timestamps', () => {
  const pre = {
    ...BASE_PREIMAGE,
    timestamp_unix: Math.floor(Date.now() / 1000) + DEFAULT_MAX_FUTURE_SKEW_SECONDS + 600,
  };
  const rec = signedReceipt(pre);
  const res = verify(rec, TRUSTED_PUBKEY, { maxAgeSeconds: 86400 });
  assert.equal(res.valid, false);
  assert.ok(res.errors.some((e) => /future/.test(e)));
});

test('fresh receipt within max_age window is accepted', () => {
  const pre = {
    ...BASE_PREIMAGE,
    timestamp_unix: Math.floor(Date.now() / 1000) - 30,
  };
  const rec = signedReceipt(pre);
  const res = verify(rec, TRUSTED_PUBKEY, { maxAgeSeconds: 3600 });
  assert.equal(res.valid, true, JSON.stringify(res.errors));
});

test('non-array proof is rejected', () => {
  const rec = signedReceipt(BASE_PREIMAGE);
  rec.proof = 'not-an-array';
  const res = verify(rec, TRUSTED_PUBKEY);
  assert.equal(res.valid, false);
  assert.ok(res.errors.some((e) => /proof must be an array/.test(e)));
});

test('proof length > MAX_PROOF_DEPTH is rejected', () => {
  const rec = signedReceipt(BASE_PREIMAGE);
  rec.proof = Array(MAX_PROOF_DEPTH + 1).fill('0'.repeat(64));
  const res = verify(rec, TRUSTED_PUBKEY);
  assert.equal(res.valid, false);
  assert.ok(res.errors.some((e) => /proof depth exceeds/.test(e)));
});

// ── AgentReadinessReceipt V1 ──────────────────────────────────────────────
// A readiness receipt attests endpoint CONFORMANCE observed at a point in time,
// never seller trustworthiness. These tests pin (a) cross-language leaf parity
// with Python readiness_receipt.compute_readiness_receipt_leaf_v1, and (b) that
// the two artifact classes cannot be confused in either direction.

const {
  verifyReadiness, recomputeReadinessLeaf, isReadinessReceipt,
  READINESS_V1_DOMAIN, KNOWN_READINESS_DOMAINS, READINESS_BASIS,
} = require('../verify_twzrd_receipt.js');

const READINESS_PRE = {
  domain: READINESS_V1_DOMAIN,
  subject_url: 'https://seller.example/api',
  basis: READINESS_BASIS,
  verdict: 'warn',
  score: 70,
  as_of_unix: 1780000000,
  recheck_after_unix: 1780000000 + 14 * 86400,
  probe_budget: 3,
  probed_count: 2,
  axes: { discovery: 'pass', capability: 'pass', commerce: 'pass', trust: 'warn', proof: 'warn' },
  resolved_pay_to: ['BJGdsDXJFy63eCAnX3UmGfShp8BuqbtkTfcamyRGr7VQ', 'AAA'],
  blocking_fix_ids: ['proof:warn', 'trust:warn'],
  commissioned_by: 'PAYER1',
  settlement_tx: 'SIG1',
  not_a_trust_vouch: true,
  ownership_proven: false,
};

// Pinned from the Python builder. If this fails, JS and Python have diverged and
// the published verifier would reject genuine receipts.
const EXPECTED_READINESS_LEAF_HEX =
  '31218d7e46ee8489f10161ff2a858f79eb583c48f539bcda941bbcbf673f2147';

function signReadiness(pre) {
  const leaf = recomputeReadinessLeaf(pre);
  const sig = nacl.sign.detached(new Uint8Array(leaf), KP.secretKey);
  return {
    version: 'v1',
    kind: 'agent_readiness',
    leaf: '0x' + leaf.toString('hex'),
    preimage: pre,
    signature: bs58.encode(Buffer.from(sig)),
    signing_pubkey: TRUSTED_PUBKEY,
  };
}

test('readiness leaf matches the Python builder byte-for-byte', () => {
  assert.equal(recomputeReadinessLeaf(READINESS_PRE).toString('hex'), EXPECTED_READINESS_LEAF_HEX);
});

test('readiness axes key order does not change the leaf', () => {
  const reversed = {};
  for (const k of Object.keys(READINESS_PRE.axes).reverse()) reversed[k] = READINESS_PRE.axes[k];
  const other = { ...READINESS_PRE, axes: reversed };
  assert.equal(
    recomputeReadinessLeaf(other).toString('hex'),
    recomputeReadinessLeaf(READINESS_PRE).toString('hex'),
  );
});

test('genuine readiness receipt verifies', () => {
  const out = verifyReadiness(signReadiness(READINESS_PRE), TRUSTED_PUBKEY);
  assert.equal(out.valid, true, JSON.stringify(out.errors));
  assert.equal(out.leaf_valid, true);
  assert.equal(out.signature_valid, true);
  assert.equal(out.not_a_trust_vouch, true);
  assert.equal(out.basis, READINESS_BASIS);
});

test('upgrading the verdict after signing is rejected', () => {
  const rec = signReadiness(READINESS_PRE);
  rec.preimage = { ...READINESS_PRE, verdict: 'ready' };
  const out = verifyReadiness(rec, TRUSTED_PUBKEY);
  assert.equal(out.valid, false);
  assert.equal(out.leaf_valid, false);
});

test('flipping an axis status after signing is rejected', () => {
  const rec = signReadiness(READINESS_PRE);
  rec.preimage = { ...READINESS_PRE, axes: { ...READINESS_PRE.axes, commerce: 'fail' } };
  const out = verifyReadiness(rec, TRUSTED_PUBKEY);
  assert.equal(out.valid, false);
  assert.equal(out.leaf_valid, false);
});

test('stripping not_a_trust_vouch is rejected', () => {
  const rec = signReadiness(READINESS_PRE);
  rec.preimage = { ...READINESS_PRE, not_a_trust_vouch: false };
  const out = verifyReadiness(rec, TRUSTED_PUBKEY);
  assert.equal(out.valid, false);
  assert.ok(out.errors.some((e) => e.includes('not_a_trust_vouch')));
});

test('deleting not_a_trust_vouch is rejected', () => {
  const rec = signReadiness({ ...READINESS_PRE });
  delete rec.preimage.not_a_trust_vouch;
  const out = verifyReadiness(rec, TRUSTED_PUBKEY);
  assert.equal(out.valid, false);
  assert.ok(out.errors.some((e) => e.includes('not_a_trust_vouch')));
});

test('flipping ownership_proven after signing is rejected', () => {
  const rec = signReadiness(READINESS_PRE);
  rec.preimage = { ...READINESS_PRE, ownership_proven: true };
  const out = verifyReadiness(rec, TRUSTED_PUBKEY);
  assert.equal(out.valid, false);
  assert.equal(out.leaf_valid, false);
  assert.ok(out.errors.some((e) => e.includes('leaf mismatch')));
});

test('deleting ownership_proven is rejected', () => {
  const rec = signReadiness({ ...READINESS_PRE });
  delete rec.preimage.ownership_proven;
  const out = verifyReadiness(rec, TRUSTED_PUBKEY);
  assert.equal(out.valid, false);
  assert.ok(out.errors.some((e) => e.includes('ownership_proven')));
});

test('readiness assertion fields require boolean values', () => {
  for (const [field, value] of [
    ['not_a_trust_vouch', 'true'],
    ['ownership_proven', 'false'],
  ]) {
    const rec = signReadiness(READINESS_PRE);
    rec.preimage = { ...READINESS_PRE, [field]: value };
    const out = verifyReadiness(rec, TRUSTED_PUBKEY);
    assert.equal(out.valid, false);
    assert.ok(out.errors.some((e) => e.includes(field)));
  }
});

test('unsigned readiness receipt is rejected', () => {
  const rec = signReadiness(READINESS_PRE);
  delete rec.signature;
  const out = verifyReadiness(rec, TRUSTED_PUBKEY);
  assert.equal(out.valid, false);
  assert.ok(out.errors.some((e) => e.includes('missing signature')));
});

test('basis cannot be relabelled to reputation', () => {
  const rec = signReadiness(READINESS_PRE);
  rec.preimage = { ...READINESS_PRE, basis: 'reputation' };
  const out = verifyReadiness(rec, TRUSTED_PUBKEY);
  assert.equal(out.valid, false);
  assert.ok(out.errors.some((e) => e.includes('own domain')));
});

test('domain sets are disjoint in both directions', () => {
  assert.ok(!KNOWN_RECEIPT_DOMAINS.has(READINESS_V1_DOMAIN));
  assert.ok(!KNOWN_READINESS_DOMAINS.has('TWZRD:AO_REPUTATION_RECEIPT_V6'));
  assert.equal(KNOWN_READINESS_DOMAINS.size, 1);
});

test('payment verifier rejects a readiness domain', () => {
  const out = verify(signReadiness(READINESS_PRE), TRUSTED_PUBKEY);
  assert.equal(out.valid, false);
  assert.ok(out.errors.some((e) => e.includes('domain')));
});

test('readiness verifier rejects a payment domain', () => {
  const rec = signReadiness(READINESS_PRE);
  rec.preimage = { ...READINESS_PRE, domain: 'TWZRD:AO_REPUTATION_RECEIPT_V6' };
  const out = verifyReadiness(rec, TRUSTED_PUBKEY);
  assert.equal(out.valid, false);
  assert.ok(out.errors.some((e) => e.includes('readiness domain')));
});

test('isReadinessReceipt discriminates the two classes', () => {
  assert.equal(isReadinessReceipt(signReadiness(READINESS_PRE)), true);
  assert.equal(isReadinessReceipt({ preimage: { domain: REPUTATION_V5_DOMAIN } }), false);
});

test('stale readiness card stays valid but is flagged past recheck', () => {
  const out = verifyReadiness(signReadiness(READINESS_PRE), TRUSTED_PUBKEY);
  assert.equal(out.valid, true);
  assert.equal(out.past_recheck_after, true);
});

// ── BOUND vs FRESHNESS card (JS parity with Python format_bound_freshness_card,
// Contract under test: the card exists in the npm verifier's output
// path, freshness names NEVER appear on a BOUND line, and a receipt whose
// JSON-only freshness fields were edited still shows them as FRESHNESS - the
// CLI must never imply they are signature-attested. Uses the real shipped
// testdata/v6_example.json (production-signed sample), so this also pins the
// card against the exact artifact strangers verify first.

const fs = require('node:fs');
const path = require('node:path');
const {
  formatBoundFreshnessCard, formatTrustedBits, boundFieldNames, freshnessFieldNames, cardVerdict,
  FRESHNESS_UNAUTHENTICATED_FIELDS: FRESH_FIELDS,
} = require('../verify_twzrd_receipt.js');

function loadV6Example() {
  const raw = fs.readFileSync(path.join(__dirname, '..', 'testdata', 'v6_example.json'), 'utf8');
  return JSON.parse(raw).twzrd_receipt;
}

test('V6 example: card lists the freshness triple as FRESHNESS, never BOUND', () => {
  const receipt = loadV6Example();
  const res = verify(receipt, receipt.signing_pubkey);
  assert.equal(res.leaf_valid, true);
  assert.equal(res.signature_valid, true);
  const card = formatBoundFreshnessCard(receipt, res);
  const lines = card.split('\n');
  for (const name of FRESH_FIELDS) {
    assert.ok(
      lines.some((l) => l.startsWith('FRESHNESS ') && l.includes(name)),
      `freshness field ${name} must appear on a FRESHNESS line`,
    );
    assert.ok(
      !lines.some((l) => l.startsWith('BOUND ') && l.includes(name)),
      `freshness field ${name} must never appear on a BOUND line`,
    );
  }
  assert.ok(lines[lines.length - 1] === 'VERDICT   valid-signature');
});

test('V6 example: reputation provenance fields are BOUND on the card', () => {
  const receipt = loadV6Example();
  const res = verify(receipt, receipt.signing_pubkey);
  const card = formatBoundFreshnessCard(receipt, res);
  for (const name of ['reputation_score', 'reputation_score_version', 'reputation_data_quality']) {
    assert.ok(
      card.split('\n').some((l) => l.startsWith('BOUND ') && l.includes(name)),
      `V6 provenance field ${name} must be BOUND`,
    );
  }
});

test('tampered freshness fields still verify but stay labeled FRESHNESS (the honesty contract)', () => {
  const receipt = loadV6Example();
  receipt.preimage = { ...receipt.preimage, staleness_days: 9999, recheck_after_unix: 1 };
  const res = verify(receipt, receipt.signing_pubkey);
  // JSON-only fields do not feed the leaf: the signature MUST still verify...
  assert.equal(res.leaf_valid, true);
  assert.equal(res.signature_valid, true);
  // ...which is exactly why the card must refuse to present them as attested.
  const card = formatBoundFreshnessCard(receipt, res);
  assert.ok(card.includes('FRESHNESS staleness_days'));
  assert.ok(card.includes('NOT signature-bound; do not treat as proof'));
  assert.ok(!card.includes('BOUND     staleness_days'));
});

test('tampered BOUND field breaks the leaf (control for the test above)', () => {
  const receipt = loadV6Example();
  receipt.preimage = { ...receipt.preimage, reputation_score: 9999 };
  const res = verify(receipt, receipt.signing_pubkey);
  assert.equal(res.leaf_valid, false);
  assert.equal(cardVerdict(receipt, res), 'invalid');
});

test('card verdict is unsigned when signature is absent', () => {
  const receipt = loadV6Example();
  delete receipt.signature;
  const res = verify(receipt, receipt.signing_pubkey);
  assert.equal(cardVerdict(receipt, res), 'unsigned');
});

test('boundFieldNames excludes freshness fields and picks the anchor that fed the leaf', () => {
  const receipt = loadV6Example();
  const pre = receipt.preimage;
  const bound = boundFieldNames(pre, true);
  for (const name of FRESH_FIELDS) assert.ok(!bound.includes(name));
  // v6 example carries settlement_tx: it, not settlement_anchor, is BOUND.
  assert.ok(bound.includes('settlement_tx') || bound.includes('settlement_anchor'));
  assert.ok(!(bound.includes('settlement_tx') && bound.includes('settlement_anchor')));
  assert.deepEqual(freshnessFieldNames(pre), [...FRESH_FIELDS]);
});

test('formatTrustedBits stays false and ignores preimage trusted_allow', () => {
  const receipt = loadV6Example();
  receipt.preimage.trusted_allow = true;
  receipt.preimage.trusted_due = true;
  receipt.preimage.freshness_bound = true;
  const bits = formatTrustedBits(receipt, { valid: true, freshness_unauthenticated: false });
  assert.equal(bits, [
    'trusted_due      : false',
    'trusted_allow    : false',
    'freshness_bound  : false',
  ].join('\n'));
});

test('spoofed V7 domain does not claim leaf-bound freshness on an invalid card', () => {
  const receipt = loadV6Example();
  receipt.preimage = {
    ...receipt.preimage,
    domain: 'TWZRD:AO_REPUTATION_RECEIPT_V7',
    version: 'v7',
    recheck_after_unix: 9999999999,
  };
  receipt.kind = 'twzrd_reputation_receipt_v7';
  receipt.version = 'v7';
  const res = verify(receipt, receipt.signing_pubkey);
  assert.equal(res.valid, false);
  const card = formatBoundFreshnessCard(receipt, res);
  assert.ok(!card.includes('covered by the V7 leaf binding'));
  assert.ok(!card.includes('BOUND     recheck_after_unix'));
  const bits = formatTrustedBits(receipt, res);
  assert.ok(bits.includes('trusted_due      : false'));
  assert.ok(bits.includes('freshness_bound  : false'));
});

test('CLI roundtrip: forged freshness stays VALID and untrusted', () => {
  const { spawnSync } = require('node:child_process');
  const os = require('node:os');
  const receipt = loadV6Example();
  receipt.preimage = {
    ...receipt.preimage,
    recheck_after_unix: 1,
    staleness_days: 99,
    score_decay_model: 'forged',
    trusted_allow: true,
  };
  const tmp = path.join(os.tmpdir(), `twzrd-cli-forge-${process.pid}.json`);
  fs.writeFileSync(tmp, JSON.stringify(receipt));
  const proc = spawnSync(process.execPath, [
    path.join(__dirname, '..', 'verify_twzrd_receipt.js'),
    tmp,
    '--pubkey',
    receipt.signing_pubkey,
  ], { encoding: 'utf8' });
  fs.unlinkSync(tmp);
  assert.equal(proc.status, 0, proc.stdout + proc.stderr);
  assert.match(proc.stdout, /FRESHNESS recheck_after_unix/);
  assert.doesNotMatch(proc.stdout, /BOUND     recheck_after_unix/);
  assert.match(proc.stdout, /trusted_due      : false/);
  assert.match(proc.stdout, /trusted_allow    : false/);
  assert.match(proc.stdout, /freshness_bound  : false/);
  assert.doesNotMatch(proc.stdout, /trusted_allow    : true/);
  assert.doesNotMatch(proc.stdout, /covered by the V7 leaf binding/);
});
