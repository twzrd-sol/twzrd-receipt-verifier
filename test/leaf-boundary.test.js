'use strict';
/**
 * Leaf-boundary mutations for the standalone JS verifier (parity with the Python verifier).
 *
 *  * Same mutation classes as the SDK leaf-boundary suite. A `_V7`
 * substring must not hide freshness from classifiers unless the hasher
 * actually bound it (exact TWZRD:AO_REPUTATION_RECEIPT_V7).
 *
 * V7 stay cold: this file does not issue a V7 leaf.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const nacl = require('tweetnacl');
const bs58 = require('bs58');
const { keccak256 } = require('js-sha3');

const {
  verify,
  recomputeLeaf,
  formatBoundFreshnessCard,
  FRESHNESS_UNAUTHENTICATED_FIELDS,
  REPUTATION_PROVENANCE_FIELDS,
  CURRENT_RECEIPT_SIGNING_KEY_ID,
  REPUTATION_V7_DOMAIN,
} = require('../verify_twzrd_receipt.js');

// The receipt-lineage document lives outside this package. When it is not
// present (standalone checkout), the doc-text assertions below are skipped and
// the verifier-tuple / keccak assertions still run.
const LINEAGE_PATH = path.join(__dirname, '../../../../docs/RECEIPT_LINEAGE.md');
const LINEAGE = fs.existsSync(LINEAGE_PATH) ? fs.readFileSync(LINEAGE_PATH, 'utf8') : null;
const VERIFIER_SRC = fs.readFileSync(
  path.join(__dirname, '../verify_twzrd_receipt.js'),
  'utf8',
);

const LOCKED_FRESHNESS = [
  'recheck_after_unix',
  'staleness_days',
  'score_decay_model',
];
const LOCKED_REPUTATION = [
  'reputation_score',
  'reputation_confidence_bps',
  'reputation_score_version',
  'reputation_feature_window_start_unix',
  'reputation_data_quality',
];

const SEED = Uint8Array.from([...Array(32).keys()]);
const KP = nacl.sign.keyPair.fromSeed(SEED);
const TRUSTED = bs58.encode(Buffer.from(KP.publicKey));
const DECAY = 'step:<=7d=1.0,<=30d=0.8,<=90d=0.5,>90d=0.25';
const NOW = 1_800_000_000;
const KECCAK_EMPTY = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

const V6_BASE = {
  domain: 'TWZRD:AO_REPUTATION_RECEIPT_V6',
  agent_id: '11111111111111111111111111111111',
  score: 72,
  confidence_bps: 8000,
  timestamp_unix: 1748736000,
  payer: '11111111111111111111111111111111',
  settlement_tx: 'EXAMPLE-sample-receipt-no-real-settlement-tx-0001',
  version: 'v6',
  reputation_score: 4242,
  reputation_confidence_bps: 7500,
  reputation_score_version: 'intel_renorm_v1',
  reputation_feature_window_start_unix: 1748000000,
  reputation_data_quality: 'high',
};

const LIVE_V5 = {
  version: 'v5',
  leaf: '0x4151f13b6e190c4ce5973e24a1336b559d26432c5c256445152334ac5cfa4755',
  preimage: {
    domain: 'TWZRD:AO_REPUTATION_RECEIPT_V5',
    agent_id: '4LkEFjJdXARkKx8FBx4LBFa2SvJNmjQpgGDLoJcypZUE',
    score: 13,
    attention_score: null,
    confidence_bps: 6500,
    timestamp_unix: 1780193750,
    payer: '4LkEFjJdXARkKx8FBx4LBFa2SvJNmjQpgGDLoJcypZUE',
    settlement_anchor: '7a676d575738466d53525a5543543558746d45725a6646316a52343543437457',
    version: 'v5',
    reputation_score: null,
    reputation_confidence_bps: null,
    reputation_score_version: 'intel_renorm_v1',
    reputation_feature_window_start_unix: null,
    reputation_data_quality:
      'agent_executions+agent_contributions+x402_solana_payer_agg+x402_solana_merchant_agg+claims',
    settlement_tx:
      '5nLx1Bzn1K6PNuUytHxx4SCJafDJTCMBw1hs3B5xnfdrMDTmTYWtHbkTzgmWW8FmSRZUCT5XtmErZfF1jR45CCtW',
  },
  signature:
    '3g5YSTJe63DWZANqs2EBrTwrSKfC3X3kykBSyYEyQGhu5iaURVBtKk3wrNSWbjcsQgxAUtPw8VTvdpXoWCYWQrhG',
  signing_pubkey: '9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf',
  key_id: 'twzrd-receipt-ed25519-v1',
  signing_alg: 'ed25519',
};

function hex(buf) {
  return Buffer.from(buf).toString('hex');
}

function signed(pre) {
  const leaf = recomputeLeaf(pre);
  const sig = nacl.sign.detached(new Uint8Array(leaf), KP.secretKey);
  return {
    version: String(pre.version || 'v6'),
    preimage: { ...pre },
    leaf: '0x' + hex(leaf),
    signature: bs58.encode(Buffer.from(sig)),
    signing_pubkey: TRUSTED,
    key_id: CURRENT_RECEIPT_SIGNING_KEY_ID,
    signing_alg: 'ed25519',
  };
}

function withFreshness(pre, recheck, days = 3) {
  return { ...pre, recheck_after_unix: recheck, staleness_days: days, score_decay_model: DECAY };
}

function cloneReceipt(r) {
  return { ...r, preimage: { ...r.preimage } };
}

function due(pre, now) {
  return pre.recheck_after_unix != null && now >= pre.recheck_after_unix;
}

function hasherBoundFreshness(pre) {
  return pre.domain === REPUTATION_V7_DOMAIN;
}

function assertNoTrustedDue(res, rec, now, label) {
  const pre = rec.preimage || {};
  const card = formatBoundFreshnessCard(rec, res);
  if (hasherBoundFreshness(pre) && res.leaf_valid === true) return;
  assert.equal(res.freshness_unauthenticated, true, `${label}: freshness_unauthenticated`);
  assert.notEqual(res.leaf_version || 'v5', 'v7', `${label}: leaf_version must not be v7`);
  if (due(pre, now)) {
    for (const name of LOCKED_FRESHNESS) {
      if (pre[name] != null) {
        assert.ok(res.unauthenticated_fields.includes(name), `${label}: missing ${name}`);
      }
    }
    assert.ok(
      !card.includes('covered by the V7 leaf binding'),
      `${label}: card claimed V7 bind`,
    );
  }
}

test('verifier tuples match locked lists', () => {
  assert.deepEqual([...FRESHNESS_UNAUTHENTICATED_FIELDS], LOCKED_FRESHNESS);
  assert.deepEqual([...REPUTATION_PROVENANCE_FIELDS], LOCKED_REPUTATION);
});

test('lineage doc matches locked lists', { skip: LINEAGE === null && 'lineage doc not in this checkout' }, () => {
  assert.match(LINEAGE, /There is no V1 to V7 ladder/);
  assert.match(LINEAGE, /`receipt_v2`\s*\|\s*0/);
  assert.match(LINEAGE, /`receipt_v3`\s*\|\s*0/);
  assert.match(LINEAGE, /`receipt_v4`\s*\|\s*0/);
});

test('names keccak256, not SHA3, as the leaf hash', () => {
  if (LINEAGE !== null) assert.match(LINEAGE, /keccak256 \(the Ethereum variant\), \*\*not\*\* SHA3/);
  assert.equal(keccak256(Buffer.alloc(0)), KECCAK_EMPTY);
  assert.notEqual(crypto.createHash('sha3-256').update(Buffer.alloc(0)).digest('hex'), KECCAK_EMPTY);
});

test('V5 verify matches documented unauthenticated algorithm', () => {
  const pre = withFreshness(LIVE_V5.preimage, LIVE_V5.preimage.timestamp_unix + 3 * 86400);
  const res = verify({ ...LIVE_V5, preimage: pre }, LIVE_V5.signing_pubkey);
  assert.equal(res.leaf_valid, true);
  assert.equal(res.leaf_version || 'v5', 'v5');
  const expected = [
    ...LOCKED_FRESHNESS.filter((n) => pre[n] != null),
    ...LOCKED_REPUTATION.filter((n) => pre[n] != null),
  ];
  assert.deepEqual([...res.unauthenticated_fields].sort(), expected.sort());
});

test('V6 verify matches documented unauthenticated algorithm', () => {
  const pre = withFreshness(V6_BASE, V6_BASE.timestamp_unix + 7 * 86400, 7);
  const rec = signed(pre);
  rec.signature = 'x';
  rec.signing_pubkey = null;
  const res = verify(rec, TRUSTED);
  assert.equal(res.leaf_valid, true);
  assert.equal(res.leaf_version || 'v6', 'v6');
  assert.deepEqual(new Set(res.unauthenticated_fields), new Set(LOCKED_FRESHNESS));
});

test('forged freshness on a live V5 signature is untrusted advice', () => {
  const forged = cloneReceipt(LIVE_V5);
  forged.preimage.recheck_after_unix = NOW - 1;
  forged.preimage.staleness_days = 99;
  forged.preimage.score_decay_model = 'forged-decay';
  const res = verify(forged, forged.signing_pubkey);
  assert.equal(res.leaf_valid, true);
  assert.equal(res.signature_valid, true);
  assert.equal(res.valid, true);
  for (const name of LOCKED_FRESHNESS) assert.ok(res.unauthenticated_fields.includes(name));
  assert.equal(due(forged.preimage, NOW), true);
  assertNoTrustedDue(res, forged, NOW, 'live V5 freshness forge');
});

test('forged freshness on a signed V6 receipt keeps the leaf', () => {
  const honestRecheck = V6_BASE.timestamp_unix + 7 * 86400;
  const rec = signed(withFreshness(V6_BASE, honestRecheck, 7));
  assert.equal(due(rec.preimage, honestRecheck - 1), false);
  const forged = cloneReceipt(rec);
  forged.preimage.recheck_after_unix = NOW - 60;
  forged.preimage.staleness_days = 1;
  forged.preimage.score_decay_model = 'PWNED';
  const res = verify(forged, TRUSTED);
  assert.equal(res.leaf_valid, true);
  assert.equal(res.signature_valid, true);
  assert.equal(res.valid, true);
  assert.equal(forged.leaf, rec.leaf);
  assert.equal(due(forged.preimage, NOW), true);
  assertNoTrustedDue(res, forged, NOW, 'signed V6 freshness forge');
});

for (const field of LOCKED_FRESHNESS) {
  test(`flipping only ${field} stays untrusted`, () => {
    const rec = signed(V6_BASE);
    const mutated = cloneReceipt(rec);
    if (field === 'score_decay_model') mutated.preimage.score_decay_model = 'x';
    else if (field === 'staleness_days') mutated.preimage.staleness_days = 1;
    else mutated.preimage.recheck_after_unix = NOW - 1;
    const res = verify(mutated, TRUSTED);
    assert.equal(res.leaf_valid, true);
    assert.ok(res.unauthenticated_fields.includes(field));
    assertNoTrustedDue(res, mutated, NOW, field);
  });
}

test('byte-flip in score_decay_model is outside the leaf', () => {
  const rec = signed(withFreshness(V6_BASE, NOW + 100));
  const mutated = cloneReceipt(rec);
  const raw = Buffer.from(mutated.preimage.score_decay_model, 'utf8');
  raw[0] ^= 0xff;
  mutated.preimage.score_decay_model = raw.toString('utf8');
  const res = verify(mutated, TRUSTED);
  assert.equal(res.leaf_valid, true);
  assertNoTrustedDue(res, mutated, NOW, 'decay byte flip');
});

test('freshness sibling swap can flip due but stays untrusted', () => {
  const recheck = NOW + 500;
  const rec = signed(withFreshness(V6_BASE, recheck, 7));
  const swapped = cloneReceipt(rec);
  swapped.preimage.recheck_after_unix = swapped.preimage.staleness_days;
  swapped.preimage.staleness_days = recheck;
  const res = verify(swapped, TRUSTED);
  assert.equal(res.leaf_valid, true);
  assert.equal(due(swapped.preimage, NOW), true);
  assertNoTrustedDue(res, swapped, NOW, 'freshness sibling swap');
});

test('sibling swap of score and reputation_score breaks the V6 leaf', () => {
  const rec = signed(withFreshness(V6_BASE, NOW - 1));
  const swapped = cloneReceipt(rec);
  swapped.preimage.score = rec.preimage.reputation_score;
  swapped.preimage.reputation_score = rec.preimage.score;
  const res = verify(swapped, TRUSTED);
  assert.equal(res.leaf_valid, false);
  assert.equal(res.valid, false);
  assertNoTrustedDue(res, swapped, NOW, 'bound sibling swap');
});

test('unused settlement_anchor is outside the leaf when settlement_tx is present', () => {
  const rec = signed(withFreshness(V6_BASE, NOW - 1));
  const mutated = cloneReceipt(rec);
  mutated.preimage.settlement_anchor = 'TAMPERED-UNUSED-ANCHOR';
  const res = verify(mutated, TRUSTED);
  assert.equal(res.leaf_valid, true);
  assert.equal(res.signature_valid, true);
  assertNoTrustedDue(res, mutated, NOW, 'unused anchor');
});

test('reordering envelope keys does not change the leaf', () => {
  const rec = signed(withFreshness(V6_BASE, NOW + 10));
  const reordered = JSON.parse(JSON.stringify({
    signing_alg: rec.signing_alg,
    signature: rec.signature,
    key_id: rec.key_id,
    preimage: {
      score_decay_model: rec.preimage.score_decay_model,
      domain: rec.preimage.domain,
      recheck_after_unix: rec.preimage.recheck_after_unix,
      payer: rec.preimage.payer,
      score: rec.preimage.score,
      staleness_days: rec.preimage.staleness_days,
      agent_id: rec.preimage.agent_id,
      confidence_bps: rec.preimage.confidence_bps,
      timestamp_unix: rec.preimage.timestamp_unix,
      settlement_tx: rec.preimage.settlement_tx,
      version: rec.preimage.version,
      reputation_score: rec.preimage.reputation_score,
      reputation_confidence_bps: rec.preimage.reputation_confidence_bps,
      reputation_score_version: rec.preimage.reputation_score_version,
      reputation_feature_window_start_unix: rec.preimage.reputation_feature_window_start_unix,
      reputation_data_quality: rec.preimage.reputation_data_quality,
    },
    leaf: rec.leaf,
    version: rec.version,
    signing_pubkey: rec.signing_pubkey,
  }));
  const res = verify(reordered, TRUSTED);
  assert.equal(res.leaf_valid, true);
  assert.equal(res.signature_valid, true);
  assert.equal(reordered.leaf, rec.leaf);
  assertNoTrustedDue(res, reordered, NOW, 'envelope reorder');
});

test('injected envelope due/trusted flags cannot manufacture trusted due', () => {
  const rec = signed(V6_BASE);
  const injected = {
    ...rec,
    due: true,
    trusted: true,
    untrusted: false,
    shouldRecheckTrusted: true,
    recheck_after_unix: 1,
  };
  const res = verify(injected, TRUSTED);
  assert.equal(due(injected.preimage, NOW), false);
  assert.ok(!res.unauthenticated_fields.includes('recheck_after_unix'));
  assertNoTrustedDue(res, injected, NOW, 'envelope due injection');
});

test('freshness placed on the envelope does not flip due', () => {
  const rec = signed(V6_BASE);
  const injected = {
    ...rec,
    recheck_after_unix: 1,
    staleness_days: 1,
    score_decay_model: DECAY,
  };
  const res = verify(injected, TRUSTED);
  assert.equal(due(injected.preimage, NOW), false);
  assert.ok(!res.unauthenticated_fields.includes('recheck_after_unix'));
  assertNoTrustedDue(res, injected, NOW, 'envelope freshness');
});

for (const kind of ['zero digest', 'keccak of JSON preimage', 'sha3-256 of leaf bytes']) {
  test(`alternate digest (${kind}) fails and cannot mint trusted due`, () => {
    const rec = signed(withFreshness(V6_BASE, NOW - 1));
    let leaf;
    if (kind === 'zero digest') leaf = '0x' + '00'.repeat(32);
    else if (kind === 'keccak of JSON preimage') {
      leaf = '0x' + keccak256(JSON.stringify(rec.preimage));
    } else {
      const body = Buffer.from(String(rec.leaf).replace(/^0x/, ''), 'hex');
      leaf = '0x' + crypto.createHash('sha3-256').update(body).digest('hex');
    }
    const mutated = { ...rec, leaf };
    const res = verify(mutated, TRUSTED);
    assert.equal(res.leaf_valid, false);
    assert.equal(res.valid, false);
    assert.equal(due(mutated.preimage, NOW), true);
    assertNoTrustedDue(res, mutated, NOW, kind);
  });
}

test('V6+_V7 domain suffix cannot hide freshness from classifiers', () => {
  const rec = signed(withFreshness(V6_BASE, NOW - 1));
  const spoofed = cloneReceipt(rec);
  spoofed.preimage.domain = 'TWZRD:AO_REPUTATION_RECEIPT_V6_V7';
  const res = verify(spoofed, TRUSTED);
  // Standalone hasher allowlists exact domains (SDK remaps `_V6`). Leaf fails.
  assert.equal(res.leaf_valid, false);
  assert.equal(res.leaf_version, 'v6');
  assert.equal(res.freshness_unauthenticated, true);
  for (const name of LOCKED_FRESHNESS) {
    assert.ok(res.unauthenticated_fields.includes(name), name);
  }
  const card = formatBoundFreshnessCard(spoofed, res);
  assert.ok(!card.includes('covered by the V7 leaf binding'));
  assert.equal(due(spoofed.preimage, NOW), true);
  assertNoTrustedDue(res, spoofed, NOW, 'V6_V7 domain spoof');
});

test('classifier source does not use a _V7 substring check', () => {
  const stripped = VERIFIER_SRC.replaceAll('TWZRD:AO_REPUTATION_RECEIPT_V7', '');
  assert.ok(!stripped.includes("includes('_V7')"));
  assert.ok(!stripped.includes('includes("_V7")'));
  assert.ok(!stripped.includes("includes('_V7')"));
  assert.ok(!/includes\(\s*['"]_V7['"]\s*\)/.test(stripped));
});

test('seeded fuzz: random outside-leaf edits never yield trusted due', () => {
  const rec = signed(withFreshness(V6_BASE, NOW + 999, 7));
  let seed = 0x26222621;
  const rng = () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  for (let i = 0; i < 48; i++) {
    const mutated = cloneReceipt(rec);
    const pick = Math.floor(rng() * 6);
    if (pick === 0) mutated.preimage.recheck_after_unix = Math.floor(rng() * NOW * 2);
    else if (pick === 1) mutated.preimage.staleness_days = Math.floor(rng() * 400);
    else if (pick === 2) mutated.preimage.score_decay_model = `fuzz-${i}-${rng().toFixed(6)}`;
    else if (pick === 3) mutated.preimage.settlement_anchor = `anchor-fuzz-${i}`;
    else if (pick === 4) {
      mutated.version = rng() > 0.5 ? 'v7' : 'v0';
      mutated.extra = 'injected';
    } else {
      mutated.leaf = '0x' + keccak256(`alt-${i}`);
    }
    const now = Math.floor(rng() * NOW * 2);
    const res = verify(mutated, TRUSTED);
    assertNoTrustedDue(res, mutated, now, `fuzz ${i}`);
    if (pick <= 3) assert.equal(res.leaf_valid, true, `fuzz ${i} leaf`);
  }
});

for (const field of ['score', 'timestamp_unix', 'reputation_score', 'confidence_bps', 'agent_id']) {
  test(`mutating bound field ${field} breaks the V6 leaf`, () => {
    const rec = signed(withFreshness(V6_BASE, NOW - 1));
    const mutated = cloneReceipt(rec);
    if (field === 'agent_id') mutated.preimage.agent_id = '22222222222222222222222222222222';
    else mutated.preimage[field] = Number(mutated.preimage[field]) + 1;
    const res = verify(mutated, TRUSTED);
    assert.equal(res.leaf_valid, false);
    assert.equal(res.valid, false);
    assertNoTrustedDue(res, mutated, NOW, `bound ${field}`);
  });
}
