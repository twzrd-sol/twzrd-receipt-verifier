'use strict';
/**
 * JS verifier library preimage-forge.
 *
 * Mutating JSON-only freshness keeps leaf+signature VALID. Trusted bits stay
 * false. evaluateRecall lives in the SDK suite; this file locks the JS
 * verifier half of the same attack.
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
  formatTrustedBits,
  formatBoundFreshnessCard,
  CURRENT_RECEIPT_SIGNING_KEY_ID,
  FRESHNESS_UNAUTHENTICATED_FIELDS,
} = require('../verify_twzrd_receipt.js');

const EXAMPLE = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../testdata/v6_example.json'), 'utf8'),
);

const SEED = Uint8Array.from([...Array(32).keys()]);
const KP = nacl.sign.keyPair.fromSeed(SEED);
const TRUSTED = bs58.encode(Buffer.from(KP.publicKey));

const V6_BASE = {
  domain: 'TWZRD:AO_REPUTATION_RECEIPT_V6',
  agent_id: '11111111111111111111111111111111',
  score: 72,
  confidence_bps: 8000,
  timestamp_unix: 1748736000,
  payer: '11111111111111111111111111111111',
  settlement_tx: 'EXAMPLE-sample-receipt-no-real-settlement-tx-0001',
  settlement_anchor: '63656970742d6e6f2d7265616c2d736574746c656d656e742d74782d30303031',
  version: 'v6',
  reputation_score: 4242,
  reputation_confidence_bps: 7500,
  reputation_score_version: 'intel_renorm_v1',
  reputation_feature_window_start_unix: 1748000000,
  reputation_data_quality: 'high',
  recheck_after_unix: 1748736000 + 3 * 86400,
  staleness_days: 3,
  score_decay_model: 'step:<=7d=1.0,<=30d=0.8,<=90d=0.5,>90d=0.25',
};

function signed(pre) {
  const leaf = recomputeLeaf(pre);
  return {
    version: pre.domain.includes('V6') ? 'v6' : 'v5',
    preimage: { ...pre },
    leaf: '0x' + Buffer.from(leaf).toString('hex'),
    signature: bs58.encode(Buffer.from(nacl.sign.detached(leaf, KP.secretKey))),
    signing_pubkey: TRUSTED,
    key_id: CURRENT_RECEIPT_SIGNING_KEY_ID,
    signing_alg: 'ed25519',
  };
}

function assertTrustedBitsFalse(res, rec) {
  const bits = formatTrustedBits(rec, res);
  assert.match(bits, /trusted_due\s+:\s+false/);
  assert.match(bits, /trusted_allow\s+:\s+false/);
  assert.match(bits, /freshness_bound\s+:\s+false/);
  const card = formatBoundFreshnessCard(rec, res);
  assert.doesNotMatch(card, /covered by the V7 leaf binding/i);
  assert.doesNotMatch(card, /BOUND\s+recheck_after_unix/);
}

function assertFieldUnauth(res, card, name) {
  assert.ok(res.unauthenticated_fields.includes(name), `${name} missing: ${res.unauthenticated_fields}`);
  assert.ok(
    card.includes(`FRESHNESS ${name}`) || card.includes(`UNAUTH    ${name}`),
    `${name} not on card:\n${card}`,
  );
}

test('production V6 envelope freshness forge stays valid and untrusted', () => {
  const rec = structuredClone(EXAMPLE.twzrd_receipt);
  rec.preimage.recheck_after_unix = 2_200_000_000;
  rec.preimage.staleness_days = 99;
  rec.preimage.score_decay_model = 'forged-never-decay';
  rec.preimage.trusted_allow = true;
  const res = verify(rec, rec.signing_pubkey);
  assert.equal(res.valid, true);
  assert.equal(res.leaf_valid, true);
  assert.equal(res.signature_valid, true);
  assert.equal(res.freshness_unauthenticated, true);
  assertTrustedBitsFalse(res, rec);
  const card = formatBoundFreshnessCard(rec, res);
  for (const name of FRESHNESS_UNAUTHENTICATED_FIELDS) {
    assertFieldUnauth(res, card, name);
  }
});

const FORGES = [
  ['recheck_after_unix', 1],
  ['recheck_after_unix', 2_200_000_000],
  ['staleness_days', 0],
  ['staleness_days', 99],
  ['score_decay_model', 'forged-never-decay'],
  ['score_decay_model', ''],
];

for (const [field, value] of FORGES) {
  test(`locally signed V6: forge ${field}=${JSON.stringify(value)} stays valid/untrusted`, () => {
    const rec = signed(V6_BASE);
    rec.preimage[field] = value;
    const res = verify(rec, TRUSTED);
    assert.equal(res.valid, true, JSON.stringify(res.errors));
    assert.equal(res.leaf_valid, true);
    assert.equal(res.signature_valid, true);
    assertTrustedBitsFalse(res, rec);
    assertFieldUnauth(res, formatBoundFreshnessCard(rec, res), field);
  });
}

test('far-future recheck forge cannot claim bound freshness', () => {
  const rec = signed(V6_BASE);
  rec.preimage.recheck_after_unix = 9_999_999_999;
  rec.preimage.trusted_allow = true;
  const res = verify(rec, TRUSTED);
  assert.equal(res.valid, true);
  assertTrustedBitsFalse(res, rec);
  assert.equal(res.freshness_unauthenticated, true);
});

test('bound score forge invalidates the leaf', () => {
  const rec = signed(V6_BASE);
  rec.preimage.score = 1;
  rec.preimage.recheck_after_unix = 1;
  const res = verify(rec, TRUSTED);
  assert.equal(res.valid, false);
  assert.equal(res.leaf_valid, false);
  assertTrustedBitsFalse(res, rec);
});

test('spoofed V7 labels do not print V7 bind', () => {
  const rec = signed(V6_BASE);
  rec.preimage.domain = 'TWZRD:AO_REPUTATION_RECEIPT_V7';
  rec.preimage.version = 'v7';
  rec.kind = 'twzrd_reputation_receipt_v7';
  rec.version = 'v7';
  rec.preimage.recheck_after_unix = 9_999_999_999;
  const res = verify(rec, TRUSTED);
  assert.equal(res.valid, false);
  assertTrustedBitsFalse(res, rec);
  const card = formatBoundFreshnessCard(rec, res);
  assert.doesNotMatch(card, /BOUND\s+recheck_after_unix/);
});
