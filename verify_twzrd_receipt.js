#!/usr/bin/env node
/*
 * Standalone offline verifier for TWZRD receipts (Node). Two receipt families,
 * auto-detected:
 *
 *   A. AO-Receipt V5/V6/V7 (trust-API) - keccak256 leaf over a packed preimage
 *      (V6 appends the reputation_* block; V7 wraps the V6 leaf with the
 *      freshness triple and requires kind 'twzrd_reputation_receipt_v7' with
 *      version and preimage.version both 'v7'),
 *      Ed25519-signed over the leaf bytes by the current receipt key (v2).
 *      Shape: { preimage, leaf, signature, signing_pubkey } (V7 also carries
 *      kind and version, compared not hashed).
 *   B. cNFT Receipt (Bubblegum anchor) - the genesis compressed-NFT receipts.
 *      Ed25519 signed DIRECTLY over a compact-JSON payload (no keccak leaf) by
 *      the airship genesis authority (2ELSDx...), signature hex-encoded.
 *      Shape: { anchor: { tier_at_mint, score_at_mint, verified_tx,
 *      behavior_proof, minted_at, signature, verify_pubkey }, ... }.
 *
 * Verifies, with NO trust in TWZRD's servers or codebase, that a receipt was
 * authored by TWZRD's published Ed25519 key and was not tampered with. Crypto
 * comes from audited libs (tweetnacl = ref Ed25519, js-sha3 = Keccak), not from
 * this script. base58 + the TWZRD byte layout are the only logic here.
 *
 *   npm install tweetnacl js-sha3 bs58
 *
 *   # trust-API receipt (A)
 *   node verify_twzrd_receipt.js receipt.json --pubkey Ak5SQwHpuQAqU7ty7ZWX7qgF39A9yi72c22KNn8sHzvS
 *   # cNFT receipt (B) - wallet is part of the signed payload but not in the
 *   #   anchor block, so pass it or name the file <wallet>.json
 *   node verify_twzrd_receipt.js zoz7...json            # wallet inferred from filename
 *   node verify_twzrd_receipt.js anchor.json --wallet zoz7neLHXoaLwNBuckSqNqaMsacpqJsphtFuNNpQyt3
 *   cat receipt.json | node verify_twzrd_receipt.js -            # stdin
 *   node verify_twzrd_receipt.js receipt.json --self-test        # tamper must fail
 *
 * Exit code 0 = VALID, 1 = INVALID / error.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const nacl = require('tweetnacl');
const { keccak256 } = require('js-sha3');
const bs58 = require('bs58');

const DEFAULT_BASE_URL = 'https://intel.twzrd.xyz';
const CURRENT_RECEIPT_SIGNING_KEY_ID = 'twzrd-receipt-ed25519-v2';
const LEGACY_RECEIPT_SIGNING_KEY_ID = 'twzrd-receipt-ed25519-v1';
const CURRENT_RECEIPT_PUBKEY = 'Ak5SQwHpuQAqU7ty7ZWX7qgF39A9yi72c22KNn8sHzvS';
const LEGACY_RECEIPT_PUBKEYS = [
  '9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf',
  '96X11cfazxwYpg2g1UodocVX9ZYpXEowDZNtKv2xRVhc',
];
const KECCAK_EMPTY = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
// Genesis cNFT receipt authority (airship). Baked in as the most paranoid form of
// out-of-band pinning: the key ships in this audited package, never fetched live.
// Override with --pubkey, or fetch the published copy with --fetch-key (cross-check).
// Matches `verify_pubkey` in every genesis anchor and the verified creator on every
// cNFT in tree 8QFdTqBkSeyuvp47dXdpwfWzXTuYSbAC64oT4soPGnXS.
const DEFAULT_CNFT_PUBKEY = '2ELSDxLkb7dYrN6EUG69tNtULAq4Fo7WPvXyrZPmuFif';
// Where --fetch-key looks for the published cNFT key descriptor.
const DEFAULT_CNFT_BASE_URL = 'https://api.twzrd.xyz';

// --- Parity with packages/twzrd-agent-intel receipt.py / receipt_signing.py ---
// Strict domain allowlist (no substring spoofing). Byte-for-byte with Python
// KNOWN_RECEIPT_DOMAINS.
const REPUTATION_V5_DOMAIN = 'TWZRD:AO_REPUTATION_RECEIPT_V5';
const ATTENTION_V5_DOMAIN = 'TWZRD:AO_ATTENTION_RECEIPT_V5';
const REPUTATION_V6_DOMAIN = 'TWZRD:AO_REPUTATION_RECEIPT_V6';
const REPUTATION_V7_DOMAIN = 'TWZRD:AO_REPUTATION_RECEIPT_V7';
const ATTENTION_V6_DOMAIN = 'TWZRD:AO_ATTENTION_RECEIPT_V6';
const KNOWN_RECEIPT_DOMAINS = new Set([
  REPUTATION_V5_DOMAIN,
  ATTENTION_V5_DOMAIN,
  REPUTATION_V6_DOMAIN,
  REPUTATION_V7_DOMAIN,
  ATTENTION_V6_DOMAIN,
]);
// AgentReadinessReceipt V1 is a SEPARATE artifact class with its OWN allowlist.
// It attests endpoint conformance observed at a point in time, NOT trust. Keeping
// the sets disjoint is what stops a readiness card being presented as paid trust
// intel (and vice versa) - mirrors Python readiness_receipt.KNOWN_READINESS_DOMAINS.
const READINESS_V1_DOMAIN = 'TWZRD:AGENT_READINESS_RECEIPT_V1';
const KNOWN_READINESS_DOMAINS = new Set([READINESS_V1_DOMAIN]);
const READINESS_BASIS = 'endpoint_conformance';
const READINESS_VERDICTS = ['ready', 'warn', 'not_ready'];
const READINESS_AXIS_STATUSES = ['pass', 'warn', 'fail'];
const MAX_READINESS_STR_UTF8 = 2048;
const MAX_READINESS_LIST_ITEMS = 64;

const LEAF_DIGEST_LEN = 32;
const PUBKEY_LEN = 32;
const SIGNATURE_LEN = 64;
const MAX_AGENT_ID_UTF8 = 256;
const MAX_PROVENANCE_STR_UTF8 = 256;
// When max_age is set, also reject timestamps too far in the future (Python
// DEFAULT_MAX_FUTURE_SKEW_SECONDS).
const DEFAULT_MAX_FUTURE_SKEW_SECONDS = 300;
const MAX_PROOF_DEPTH = 32;

// Leaf-bound vs JSON-only. Bound scores: prefix score u16 (leaf) vs
// reputation_score i64 (V6 block). Freshness triple is JSON-only.
const REPUTATION_PROVENANCE_FIELDS = [
  'reputation_score',
  'reputation_confidence_bps',
  'reputation_score_version',
  'reputation_feature_window_start_unix',
  'reputation_data_quality',
];
const FRESHNESS_UNAUTHENTICATED_FIELDS = [
  'recheck_after_unix',
  'staleness_days',
  'score_decay_model',
];

function hashedLeafBinding(pre) {
  // Binding follows recomputeLeaf, not a display-domain spoof.
  // Freshness is hashed only on the exact V7 constant. A suffix like
  // `_V6_V7` is not V7 — the hasher never special-cases a `_V7` substring.
  if (pre && pre.domain === REPUTATION_V7_DOMAIN) return 'v7';
  const domainUpper = String((pre && pre.domain) || '').toUpperCase();
  if (domainUpper.includes('_V6')) return 'v6';
  return 'v5';
}

function unauthenticatedFields(pre, isV6) {
  if (hashedLeafBinding(pre) === 'v7') return [];
  const present = (name) => pre[name] !== null && pre[name] !== undefined;
  const names = FRESHNESS_UNAUTHENTICATED_FIELDS.filter(present);
  if (!isV6) names.push(...REPUTATION_PROVENANCE_FIELDS.filter(present));
  return names;
}

function classifyLeafBinding(pre) {
  const leafVersion = hashedLeafBinding(pre);
  return {
    leaf_version: leafVersion,
    unauthenticated_fields: unauthenticatedFields(pre, leafVersion === 'v6'),
    freshness_unauthenticated: leafVersion !== 'v7',
  };
}

// Named preimage keys encoded in the V5 leaf prefix (see RECEIPT_V6_LEAF_SPEC.md).
// `score` and `attention_score` share the same u16 slot; only one applies.
// Mirrors Python V5_PREFIX_BOUND_FIELDS byte-for-byte.
const V5_PREFIX_BOUND_FIELDS = [
  'domain',
  'agent_id',
  'score',
  'attention_score',
  'confidence_bps',
  'timestamp_unix',
  'payer',
  'settlement_tx',
  'settlement_anchor',
];

// Leaf-covered preimage keys. Never includes FRESHNESS_UNAUTHENTICATED_FIELDS.
// Mirrors Python bound_field_names().
function boundFieldNames(pre, isV6) {
  const domainStr = String(pre.domain || '').toUpperCase();
  const isAttention = domainStr.includes('ATTENTION');
  const names = [];
  for (const name of V5_PREFIX_BOUND_FIELDS) {
    if (name === 'score' && isAttention) continue;
    if (name === 'attention_score' && !isAttention) continue;
    if (name === 'settlement_tx' || name === 'settlement_anchor') continue;
    if (name === 'domain' || name in pre) names.push(name);
  }
  // recomputeLeaf hashes _anchor32(settlement_tx or settlement_anchor).
  // Only the key that actually fed the leaf is BOUND.
  if (pre.settlement_tx) names.push('settlement_tx');
  else if (pre.settlement_anchor !== null && pre.settlement_anchor !== undefined) names.push('settlement_anchor');
  if (isV6 || pre.domain === REPUTATION_V7_DOMAIN) names.push(...REPUTATION_PROVENANCE_FIELDS);
  return names;
}

// Freshness keys actually present. V6: JSON-only; V7: bound into the leaf.
// Mirrors Python freshness_field_names().
function freshnessFieldNames(pre) {
  return FRESHNESS_UNAUTHENTICATED_FIELDS.filter(
    (n) => pre[n] !== null && pre[n] !== undefined,
  );
}

// Crypto verdict only. Age/policy errors do not change this label.
// Mirrors Python card_verdict().
function cardVerdict(receipt, res) {
  if (!receipt.signature) return 'unsigned';
  if (res.leaf_valid && res.signature_valid) return 'valid-signature';
  return 'invalid';
}

// Consumption bits. Never read trusted_* from the receipt JSON.
// Mirrors Python format_trusted_bits(). Constant false on V5, V6 and genuine V7
// alike: V7 issuance is live (free sample + paid /trust; no external buyer has
// paid for a V7 receipt yet) but these are consumption bits, not a crypto
// readout; trusted_due is never computed here.
function formatTrustedBits(_receipt, _res) {
  return [
    'trusted_due      : false',
    'trusted_allow    : false',
    'freshness_bound  : false',
  ].join('\n');
}

// Host-facing card. Freshness names must never appear on a BOUND line.
// Mirrors Python format_bound_freshness_card() line-for-line.
function formatBoundFreshnessCard(receipt, res) {
  const pre = receipt.preimage || {};
  const binding = hashedLeafBinding(pre);
  const isV6 = binding === 'v6' || binding === 'v7';
  const bound = boundFieldNames(pre, isV6);
  const fresh = freshnessFieldNames(pre);
  // Schema coverage is not a consumption allow. Only a valid verify whose
  // freshness is actually leaf-bound may claim the V7 note.
  // Missing flag means unauthenticated (do not treat `!undefined` as bound).
  const freshnessBound = !!res.valid && res.freshness_unauthenticated === false;
  const lines = [];
  for (const name of bound) {
    lines.push(`BOUND     ${name}   covered by Ed25519 over the signed payload`);
  }
  for (const name of fresh) {
    const note = freshnessBound
      ? 'covered by the V7 leaf binding'
      : 'present, NOT signature-bound; do not treat as proof';
    lines.push(`FRESHNESS ${name}   ${note}`);
  }
  const listed = new Set(fresh);
  for (const name of res.unauthenticated_fields || []) {
    if (listed.has(name) || bound.includes(name)) continue;
    lines.push(`UNAUTH    ${name}   present, NOT signature-bound; do not treat as proof`);
    listed.add(name);
  }
  lines.push(`VERDICT   ${cardVerdict(receipt, res)}`);
  return lines.join('\n');
}

function b58decode(s) { return Buffer.from(bs58.decode(s)); }

function u16le(n) { const b = Buffer.alloc(2); b.writeUInt16LE(n & 0xffff, 0); return b; }
function u64le(n) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n), 0); return b; }
function i64le(n) { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n), 0); return b; }

// V6 reputation block: 1-byte presence flag (0x00 null / 0x01 present) + fixed-width
// value when present. reputation_score is i64 LE (null-vs-0 safe); version/quality
// are u16-len-prefixed UTF-8; feature_window is u64 LE. "" is present (distinct from
// null). Mirrors the issuer's RECEIPT_V6_LEAF_SPEC.md byte layout exactly.
function encodeReputationBlockV6(pre) {
  const optInt = (v, enc) => (v === null || v === undefined)
    ? Buffer.from([0x00])
    : Buffer.concat([Buffer.from([0x01]), enc(v)]);
  const optStr = (v) => {
    if (v === null || v === undefined) return Buffer.from([0x00]);
    const raw = Buffer.from(String(v), 'utf8');
    if (raw.length > MAX_PROVENANCE_STR_UTF8) {
      throw new Error(
        `provenance string exceeds MAX_PROVENANCE_STR_UTF8=${MAX_PROVENANCE_STR_UTF8} (got ${raw.length})`,
      );
    }
    return Buffer.concat([Buffer.from([0x01]), u16le(raw.length), raw]);
  };
  return Buffer.concat([
    optInt(pre.reputation_score, i64le),
    optInt(pre.reputation_confidence_bps, u16le),
    optStr(pre.reputation_score_version),
    optInt(pre.reputation_feature_window_start_unix, u64le),
    optStr(pre.reputation_data_quality),
  ]);
}

function payer32(payer) {
  try { const raw = b58decode(payer); if (raw.length === 32) return raw; } catch (_) {}
  return crypto.createHash('sha256').update(payer, 'utf8').digest();
}

function anchor32(tx) {
  if (!tx) return Buffer.alloc(32);
  const raw = Buffer.from(tx, 'utf8');
  if (raw.length >= 32) return raw.subarray(raw.length - 32);
  return Buffer.concat([Buffer.alloc(32 - raw.length), raw]);
}

function canonicalFreshnessV7(pre) {
  for (const name of ['timestamp_unix', 'staleness_days', 'recheck_after_unix']) {
    if (!Number.isSafeInteger(pre[name]) || pre[name] < 0) throw new Error(`${name} must be a nonnegative safe integer`);
  }
  if (pre.staleness_days > 65535 || pre.recheck_after_unix !== pre.timestamp_unix + pre.staleness_days * 86400) {
    throw new Error('invalid V7 freshness boundary');
  }
  if (typeof pre.score_decay_model !== 'string' || !/^[\x20-\x7e]{1,256}$/.test(pre.score_decay_model)) {
    throw new Error('score_decay_model must be 1..256 printable ASCII characters');
  }
  return Buffer.from(JSON.stringify({recheck_after_unix: pre.recheck_after_unix,
    score_decay_model: pre.score_decay_model, staleness_days: pre.staleness_days}), 'utf8');
}

function recomputeLeaf(pre, anchorOverride) {
  if (pre.domain === REPUTATION_V7_DOMAIN) {
    validateV7Base(pre);
    const fresh = canonicalFreshnessV7(pre);
    const anchor = pre.settlement_tx ? anchor32(pre.settlement_tx) : Buffer.from(pre.settlement_anchor || '', 'hex');
    if (anchor.length !== 32) throw new Error('V7 settlement_anchor must be 32 bytes');
    const base = recomputeLeaf({...pre, domain: REPUTATION_V6_DOMAIN}, anchor);
    const length = Buffer.alloc(4); length.writeUInt32LE(fresh.length);
    return Buffer.from(keccak256.arrayBuffer(Buffer.concat([Buffer.from(REPUTATION_V7_DOMAIN), base, length, fresh])));
  }
  // Strict allowlist only — mirrors Python verify_receipt / leaf builders.
  // V6 binds reputation_* into the leaf (V5 left them unsigned/forgeable).
  const domainStr = String(pre.domain || '');
  if (!KNOWN_RECEIPT_DOMAINS.has(domainStr)) {
    throw new Error(`unknown or non-canonical domain in preimage: ${JSON.stringify(domainStr)}`);
  }
  const isV6 = domainStr === REPUTATION_V6_DOMAIN || domainStr === ATTENTION_V6_DOMAIN;
  const isAttention = domainStr === ATTENTION_V5_DOMAIN || domainStr === ATTENTION_V6_DOMAIN;
  const domain = Buffer.from(domainStr, 'ascii');
  const score = isAttention ? (pre.attention_score || 0) : (pre.score || 0);
  if (pre.agent_id === null || pre.agent_id === undefined) {
    throw new Error('agent_id must not be null');
  }
  const agent = Buffer.from(String(pre.agent_id), 'utf8');
  if (agent.length > MAX_AGENT_ID_UTF8) {
    throw new Error(
      `agent_id exceeds MAX_AGENT_ID_UTF8=${MAX_AGENT_ID_UTF8} (got ${agent.length} utf-8 bytes)`,
    );
  }
  const conf = Number(pre.confidence_bps);
  if (!Number.isFinite(conf) || conf < 0 || conf > 10000) {
    throw new Error(`confidence_bps out of range 0..10000 (got ${pre.confidence_bps})`);
  }
  const parts = [
    domain,
    u16le(agent.length), agent,
    u16le(score),
    u16le(conf),
    u64le(pre.timestamp_unix),
    payer32(pre.payer),
    anchorOverride || anchor32(pre.settlement_tx || pre.settlement_anchor),
  ];
  if (isV6) parts.push(encodeReputationBlockV6(pre));
  return Buffer.from(keccak256.arrayBuffer(Buffer.concat(parts)));
}

function validateV7Base(pre) {
  for (const [name, lo, hi, required] of [
    ['score', 0, 65535, true], ['confidence_bps', 0, 10000, true],
    ['timestamp_unix', 0, Number.MAX_SAFE_INTEGER, true],
    ['reputation_score', -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, false],
    ['reputation_confidence_bps', 0, 65535, false],
    ['reputation_feature_window_start_unix', 0, Number.MAX_SAFE_INTEGER, false],
  ]) {
    const value = pre[name];
    if ((value === null || value === undefined) && !required) continue;
    if (!Number.isSafeInteger(value) || value < lo || value > hi) throw new Error(`invalid V7 ${name}`);
  }
  for (const name of ['agent_id', 'reputation_score_version', 'reputation_data_quality']) {
    const value = pre[name];
    if ((value === null || value === undefined) && name !== 'agent_id') continue;
    if (typeof value !== 'string' || Buffer.byteLength(value) > 256 || Buffer.from(value).toString('utf8') !== value) throw new Error(`invalid V7 ${name}`);
  }
  // Marker payers are contractual; payer32() already hashes them to a stable 32
  // bytes, matching V5/V6 and the issuer. A strict decode here made marker-payer
  // V7 receipts unverifiable in JS while Python accepted them.
  if (typeof pre.payer !== 'string' || !pre.payer || Buffer.byteLength(pre.payer, 'utf8') > 256) throw new Error('invalid V7 payer');
}

function fetchPublishedPubkey(baseUrl) {
  const base = baseUrl.replace(/\/+$/, '');
  const paths = [
    '/.well-known/twzrd-receipt-pubkey',
    '/v1/intel/pubkey',
    '/.well-known/x402',
  ];
  const headers = { 'User-Agent': 'twzrd-receipt-verifier/1.0' };

  function fetchPath(i) {
    if (i >= paths.length) return Promise.reject(new Error('no pubkey endpoint responded'));
    const path = paths[i];
    return new Promise((resolve, reject) => {
      https.get(base + path, { headers }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          try {
            const doc = JSON.parse(body);
            resolve(path.endsWith('/x402')
              ? doc.receipt.signature.public_key
              : doc.public_key);
          } catch (e) {
            reject(e);
          }
        });
      }).on('error', (err) => fetchPath(i + 1).then(resolve, reject));
    });
  }
  return fetchPath(0);
}

// Fetch the published cNFT signing key descriptor (for --fetch-key). Returns the
// base58 pubkey. This trades package-trust for domain/TLS-trust; the built-in key is
// the default precisely because it needs no network. Use this to CROSS-CHECK the
// built-in, or to pin to whatever the live domain currently publishes.
function fetchCnftPubkey(baseUrl) {
  const base = baseUrl.replace(/\/+$/, '');
  const paths = ['/v1/receipts/pubkey', '/.well-known/twzrd-receipt-pubkey'];
  const headers = { 'User-Agent': 'twzrd-receipt-verifier/cnft' };
  function fetchPath(i) {
    if (i >= paths.length) return Promise.reject(new Error('no cNFT pubkey endpoint responded'));
    return new Promise((resolve, reject) => {
      https.get(base + paths[i], { headers }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          try {
            const pk = JSON.parse(body).public_key;
            if (pk) resolve(pk); else throw new Error('no public_key field');
          } catch (e) { fetchPath(i + 1).then(resolve, reject); }
        });
      }).on('error', () => fetchPath(i + 1).then(resolve, reject));
    });
  }
  return fetchPath(0);
}

/**
 * Verify an AO-Receipt V5/V6/V7 (trust-API) payload. On V7 the freshness
 * triple is leaf-bound (res.freshness_unauthenticated === false,
 * res.unauthenticated_fields === []); on V5/V6 it is JSON-only.
 *
 * @param {object} receipt
 * @param {string} trustedPubkey base58 Ed25519 pubkey
 * @param {{ maxAgeSeconds?: number, maxFutureSkewSeconds?: number }} [opts]
 *   maxAgeSeconds: when > 0, reject receipts older than this many seconds and
 *   also reject timestamps more than maxFutureSkewSeconds into the future
 *   (default 300). Mirrors Python verify_receipt(..., max_age_seconds=...).
 */
// --- AgentReadinessReceipt V1 -------------------------------------------------
// Byte layout mirrors Python readiness_receipt.compute_readiness_receipt_leaf_v1.
// Keep the two in lockstep; the cross-language golden test asserts equality.

function reqStr(value) {
  const raw = Buffer.from(String(value), 'utf8');
  if (raw.length > MAX_READINESS_STR_UTF8) {
    throw new Error(`string exceeds MAX_READINESS_STR_UTF8=${MAX_READINESS_STR_UTF8} (got ${raw.length} utf-8 bytes)`);
  }
  return Buffer.concat([u16le(raw.length), raw]);
}

function optStr(value) {
  if (value === null || value === undefined) return Buffer.from([0x00]);
  return Buffer.concat([Buffer.from([0x01]), reqStr(value)]);
}

function strList(values) {
  const items = Array.isArray(values) ? values : [];
  if (items.length > MAX_READINESS_LIST_ITEMS) {
    throw new Error(`list exceeds MAX_READINESS_LIST_ITEMS=${MAX_READINESS_LIST_ITEMS} (got ${items.length})`);
  }
  return Buffer.concat([u16le(items.length), ...items.map((i) => reqStr(i))]);
}

function axesBlock(axes) {
  const obj = axes && typeof axes === 'object' ? axes : {};
  // Sorted by axis name so object key order cannot fork the leaf.
  const names = Object.keys(obj).sort();
  if (names.length > MAX_READINESS_LIST_ITEMS) {
    throw new Error(`too many axes (got ${names.length})`);
  }
  const parts = [u16le(names.length)];
  for (const name of names) {
    const status = obj[name];
    const idx = READINESS_AXIS_STATUSES.indexOf(status);
    if (idx < 0) throw new Error(`axis ${JSON.stringify(name)} has invalid status ${JSON.stringify(status)}`);
    parts.push(reqStr(name), Buffer.from([idx]));
  }
  return Buffer.concat(parts);
}

function boolByte(value, name) {
  if (typeof value !== 'boolean') {
    throw new Error(`${name} must be a boolean`);
  }
  return Buffer.from([value ? 0x01 : 0x00]);
}

function recomputeReadinessLeaf(pre) {
  const domainStr = String(pre.domain || '');
  if (!KNOWN_READINESS_DOMAINS.has(domainStr)) {
    throw new Error(`unknown or non-canonical readiness domain in preimage: ${JSON.stringify(domainStr)}`);
  }
  const basis = String(pre.basis || '');
  if (basis !== READINESS_BASIS) {
    throw new Error(`basis must be ${JSON.stringify(READINESS_BASIS)} for a readiness receipt (got ${JSON.stringify(basis)}) - a different claim class needs its own domain`);
  }
  if (pre.not_a_trust_vouch !== true) {
    throw new Error('not_a_trust_vouch must be the boolean true');
  }
  const vIdx = READINESS_VERDICTS.indexOf(pre.verdict);
  if (vIdx < 0) throw new Error(`verdict must be one of ${READINESS_VERDICTS.join(',')} (got ${JSON.stringify(pre.verdict)})`);
  const score = Math.max(0, Math.min(65535, Number(pre.score) || 0));
  const clampByte = (n) => Math.max(0, Math.min(255, Number(n) || 0));
  const parts = [
    Buffer.from(domainStr, 'ascii'),
    reqStr(pre.subject_url),
    reqStr(basis),
    boolByte(pre.not_a_trust_vouch, 'not_a_trust_vouch'),
    boolByte(pre.ownership_proven, 'ownership_proven'),
    Buffer.from([vIdx]),
    u16le(score),
    u64le(Math.max(0, Number(pre.as_of_unix) || 0)),
    u64le(Math.max(0, Number(pre.recheck_after_unix) || 0)),
    Buffer.from([clampByte(pre.probe_budget)]),
    Buffer.from([clampByte(pre.probed_count)]),
    axesBlock(pre.axes),
    strList(pre.resolved_pay_to),
    strList(pre.blocking_fix_ids),
    optStr(pre.commissioned_by),
    optStr(pre.settlement_tx),
  ];
  return Buffer.from(keccak256.arrayBuffer(Buffer.concat(parts)));
}

function isReadinessReceipt(receipt) {
  const pre = (receipt && receipt.preimage) || {};
  return KNOWN_READINESS_DOMAINS.has(String(pre.domain || ''));
}

function receiptKeyCandidates(trustedPubkey, keyId) {
  if (keyId && keyId !== CURRENT_RECEIPT_SIGNING_KEY_ID && keyId !== LEGACY_RECEIPT_SIGNING_KEY_ID) {
    return { keys: [], error: `unknown receipt signing key_id ${keyId}` };
  }
  // A non-current trustedPubkey is an explicit out-of-band override (for tests
  // or an operator-pinned historical key), so do not silently widen it.
  if (trustedPubkey !== CURRENT_RECEIPT_PUBKEY) {
    return { keys: [trustedPubkey] };
  }
  if (keyId === CURRENT_RECEIPT_SIGNING_KEY_ID) return { keys: [trustedPubkey] };
  if (keyId === LEGACY_RECEIPT_SIGNING_KEY_ID) return { keys: LEGACY_RECEIPT_PUBKEYS };
  if (!keyId) return { keys: [trustedPubkey, ...LEGACY_RECEIPT_PUBKEYS] };
  return { keys: [], error: `unknown receipt signing key_id ${keyId}` };
}

function verifyReadiness(receipt, trustedPubkey, opts) {
  const options = opts && typeof opts === 'object' ? opts : {};
  const maxAgeSeconds = Number(options.maxAgeSeconds) > 0 ? Number(options.maxAgeSeconds) : 0;
  const out = {
    kind: 'agent_readiness',
    leaf_valid: false,
    signature_valid: false,
    errors: [],
    trusted_pubkey: trustedPubkey,
  };
  const pre = (receipt && receipt.preimage) || {};
  const leafHex = String((receipt && receipt.leaf) || '').toLowerCase().replace(/^0x/, '');

  if (!KNOWN_READINESS_DOMAINS.has(String(pre.domain || ''))) {
    out.errors.push(`unknown or non-canonical readiness domain in preimage: ${JSON.stringify(String(pre.domain || ''))}`);
    out.valid = false;
    return out;
  }
  // The disclaimer is structural, not decorative: a readiness receipt that
  // claims to be a trust vouch is not a valid readiness receipt.
  if (pre.not_a_trust_vouch !== true) {
    out.errors.push('not_a_trust_vouch must be true for a readiness receipt');
    out.valid = false;
    return out;
  }
  if (!/^[0-9a-f]{64}$/.test(leafHex)) {
    out.errors.push('leaf must be 64 hex chars (with or without 0x)');
  }

  let recomputed;
  try { recomputed = recomputeReadinessLeaf(pre); }
  catch (e) { out.errors.push('could not recompute leaf: ' + e.message); out.valid = false; return out; }
  out.recomputed_leaf = '0x' + recomputed.toString('hex');
  out.leaf_valid = recomputed.toString('hex') === leafHex;
  if (!out.leaf_valid) out.errors.push('leaf mismatch: preimage does not hash to receipt.leaf');

  const sig = receipt && receipt.signature;
  if (!sig) {
    out.errors.push('missing signature (unsigned receipts are rejected)');
    out.valid = false;
    return out;
  }
  const embedded = receipt.signing_pubkey;
  const keySet = receiptKeyCandidates(trustedPubkey, receipt.key_id);
  if (keySet.error) {
    out.errors.push(keySet.error);
    out.valid = false;
    return out;
  }
  if (embedded && !keySet.keys.includes(embedded)) {
    out.errors.push(`signing_pubkey ${embedded} is not trusted for key_id ${receipt.key_id || '(unspecified)'}`);
    out.valid = false;
    return out;
  }
  let sigRaw;
  try { sigRaw = b58decode(sig); }
  catch (e) {
    out.errors.push('malformed signature encoding: ' + e.message);
    out.valid = false;
    return out;
  }
  if (sigRaw.length !== SIGNATURE_LEN) {
    out.errors.push('malformed signature length');
    out.valid = false;
    return out;
  }
  try {
    const candidates = embedded ? [embedded] : keySet.keys;
    out.signature_valid = candidates.some((key) => {
      const pkRaw = b58decode(key);
      return pkRaw.length === PUBKEY_LEN && nacl.sign.detached.verify(
        new Uint8Array(recomputed), new Uint8Array(sigRaw), new Uint8Array(pkRaw),
      );
    });
  } catch (e) {
    out.errors.push('signature check error: ' + e.message);
    out.valid = false;
    return out;
  }
  if (!out.signature_valid) out.errors.push('signature does not verify against the trusted published key');

  if (maxAgeSeconds > 0) {
    const age = Math.abs(Math.floor(Date.now() / 1000) - (Number(pre.as_of_unix) || 0));
    if (age > maxAgeSeconds) out.errors.push(`as_of_unix is ${age}s from now, exceeds max_age_seconds=${maxAgeSeconds}`);
  }

  // Advisory only: a genuine but stale card stays cryptographically valid.
  out.past_recheck_after = Math.floor(Date.now() / 1000) >= (Number(pre.recheck_after_unix) || 0);
  out.basis = basisOf(pre);
  out.verdict = pre.verdict;
  out.subject_url = pre.subject_url;
  out.not_a_trust_vouch = pre.not_a_trust_vouch;
  out.ownership_proven = pre.ownership_proven;
  out.valid = out.leaf_valid && out.signature_valid && out.errors.length === 0;
  return out;
}

function basisOf(pre) { return String(pre.basis || ''); }

function verify(receipt, trustedPubkey, opts) {
  const options = opts && typeof opts === 'object' ? opts : {};
  const maxAgeSeconds = Number(options.maxAgeSeconds) > 0 ? Number(options.maxAgeSeconds) : 0;
  const maxFutureSkew = Number.isFinite(Number(options.maxFutureSkewSeconds))
    ? Number(options.maxFutureSkewSeconds)
    : DEFAULT_MAX_FUTURE_SKEW_SECONDS;

  const out = {
    leaf_valid: false,
    signature_valid: false,
    errors: [],
    trusted_pubkey: trustedPubkey,
    unauthenticated_fields: [],
    freshness_unauthenticated: true,
    leaf_version: 'v5',
    valid: false,
  };
  const pre = receipt.preimage || {};
  const leafHex = String(receipt.leaf || '').toLowerCase().replace(/^0x/, '');
  // Classify from hasher rules before any early return. A `_V6_V7` suffix
  // is unknown to the allowlist; empty unauthenticated_fields plus a missing
  // freshness flag would look like a V7 bind (#2650).
  const classified = classifyLeafBinding(pre);
  out.leaf_version = classified.leaf_version;
  out.unauthenticated_fields = classified.unauthenticated_fields;
  out.freshness_unauthenticated = classified.freshness_unauthenticated;
  if (pre.domain === REPUTATION_V7_DOMAIN && (receipt.kind !== 'twzrd_reputation_receipt_v7' || receipt.version !== 'v7' || pre.version !== 'v7')) {
    out.errors.push('V7 kind/version mismatch');
    return out;
  }

  // Strict domain allowlist before hash work (Python KNOWN_RECEIPT_DOMAINS).
  const domainStr = String(pre.domain || '');
  if (!KNOWN_RECEIPT_DOMAINS.has(domainStr)) {
    out.errors.push(`unknown or non-canonical domain in preimage: ${JSON.stringify(domainStr)}`);
    out.valid = false;
    return out;
  }

  // Merkle proof depth bound (parity with Python MerkleTree MAX_PROOF_DEPTH)
  if (receipt.proof !== undefined && receipt.proof !== null) {
    if (!Array.isArray(receipt.proof)) {
      out.errors.push('proof must be an array');
      out.valid = false;
      return out;
    }
    if (receipt.proof.length > MAX_PROOF_DEPTH) {
      out.errors.push(`proof depth exceeds MAX_PROOF_DEPTH=${MAX_PROOF_DEPTH} (got ${receipt.proof.length})`);
      out.valid = false;
      return out;
    }
  }

  // Explicit UTF-8 byte length cap for provenance (when present in preimage)
  if (pre.provenance !== undefined && pre.provenance !== null) {
    const provLen = Buffer.byteLength(String(pre.provenance), 'utf8');
    if (provLen > MAX_PROVENANCE_STR_UTF8) {
      out.errors.push(`provenance exceeds MAX_PROVENANCE_STR_UTF8=${MAX_PROVENANCE_STR_UTF8} (got ${provLen})`);
      out.valid = false;
      return out;
    }
  }

  if (!/^[0-9a-f]{64}$/.test(leafHex)) {
    out.errors.push('leaf must be 64 hex chars (with or without 0x)');
  }

  let recomputed;
  try { recomputed = recomputeLeaf(pre); }
  catch (e) { out.errors.push('could not recompute leaf: ' + e.message); return out; }
  if (recomputed.length !== LEAF_DIGEST_LEN) {
    out.errors.push(`recomputed leaf must be ${LEAF_DIGEST_LEN} bytes`);
    return out;
  }
  out.recomputed_leaf = '0x' + recomputed.toString('hex');
  out.leaf_valid = recomputed.toString('hex') === leafHex;
  if (!out.leaf_valid) out.errors.push('leaf mismatch: preimage does not hash to receipt.leaf');

  const sig = receipt.signature;
  if (!sig) {
    out.errors.push('missing signature (unsigned receipts are rejected)');
    out.valid = false;
    return out;
  }

  const embedded = receipt.signing_pubkey;
  const keySet = receiptKeyCandidates(trustedPubkey, receipt.key_id);
  if (keySet.error) {
    out.errors.push(keySet.error);
    out.signature_valid = false;
    out.valid = false;
    return out;
  }
  if (embedded && !keySet.keys.includes(embedded)) {
    out.errors.push(`signing_pubkey ${embedded} is not trusted for key_id ${receipt.key_id || '(unspecified)'}`);
    out.signature_valid = false;
    out.valid = false;
    return out;
  }

  let sigRaw;
  try {
    sigRaw = b58decode(sig);
  } catch (e) {
    out.errors.push('malformed signature encoding: ' + e.message);
    out.signature_valid = false;
    out.valid = false;
    return out;
  }
  if (sigRaw.length !== SIGNATURE_LEN) {
    out.errors.push(`malformed signature length: ${sigRaw.length} (expected ${SIGNATURE_LEN})`);
    out.signature_valid = false;
    out.valid = false;
    return out;
  }

  try {
    const candidates = embedded ? [embedded] : keySet.keys;
    out.signature_valid = candidates.some((key) => {
      const pkRaw = b58decode(key);
      return pkRaw.length === PUBKEY_LEN && nacl.sign.detached.verify(
        new Uint8Array(recomputed), new Uint8Array(sigRaw), new Uint8Array(pkRaw),
      );
    });
  } catch (e) {
    out.errors.push('signature check error: ' + e.message);
    out.signature_valid = false;
    out.valid = false;
    return out;
  }
  if (!out.signature_valid) out.errors.push('signature not valid for the trusted receipt key set');

  // Opt-in freshness + future-skew (Python max_age_seconds + DEFAULT_MAX_FUTURE_SKEW).
  if (maxAgeSeconds > 0) {
    const ts = Number(pre.timestamp_unix);
    if (!Number.isFinite(ts) || ts <= 0) {
      out.errors.push(`max_age_seconds ${maxAgeSeconds} set but receipt has no valid timestamp_unix`);
    } else {
      const now = Math.floor(Date.now() / 1000);
      if (ts > now + maxFutureSkew) {
        out.errors.push(
          `receipt timestamp in the future (ts=${ts} > now+skew=${now + maxFutureSkew})`,
        );
      }
      const age = Math.abs(now - ts);
      if (age > maxAgeSeconds) {
        out.errors.push(`receipt too old (age ${age}s > max_age_seconds ${maxAgeSeconds})`);
      }
    }
  }

  out.valid = out.leaf_valid && out.signature_valid && out.errors.length === 0;
  return out;
}

// ── cNFT (Bubblegum anchor) receipt ───────────────────────────────────────
// The genesis compressed-NFT receipts are NOT keccak-leaf receipts. Each is an
// Ed25519 signature made DIRECTLY over the UTF-8 bytes of a compact JSON object,
// in this EXACT key order (JSON.stringify defaults: no spaces). Do not reorder.
const CNFT_SIGNED_FIELDS = ['wallet', 'tier_at_mint', 'score_at_mint', 'verified_tx', 'behavior_proof', 'minted_at'];

// A cNFT receipt is the metadata JSON served at /r/<wallet>.json: it carries an
// `anchor` block (at-mint snapshot + signature) instead of a keccak `leaf`.
function isCnftReceipt(receipt) {
  const a = receipt && receipt.anchor;
  return !!(a && typeof a === 'object' && a.signature &&
    (a.tier_at_mint !== undefined || a.score_at_mint !== undefined));
}

// Reconstruct the exact bytes the issuer signed (airship.ts). `wallet` is the
// first signed field but is NOT stored in the anchor block (it is the leaf owner /
// the <wallet>.json filename), so it must be supplied by the caller.
function cnftSignedPayload(anchor, wallet) {
  return Buffer.from(JSON.stringify({
    wallet,
    tier_at_mint: anchor.tier_at_mint,
    score_at_mint: anchor.score_at_mint,
    verified_tx: anchor.verified_tx,
    behavior_proof: anchor.behavior_proof,
    minted_at: anchor.minted_at,
  }), 'utf8');
}

// Resolve the wallet from (in priority): explicit --wallet, the receipt body (if a
// future format embeds it), or the <wallet>.json filename. Only accepts a filename
// stem that base58-decodes to a 32-byte pubkey, so a stray filename can't be passed
// off as the signed wallet.
function resolveWallet({ explicitWallet, receipt, receiptPath } = {}) {
  if (explicitWallet) return { wallet: explicitWallet, src: '--wallet' };
  if (receipt && typeof receipt.wallet === 'string') return { wallet: receipt.wallet, src: 'receipt.wallet' };
  if (receipt && receipt.anchor && typeof receipt.anchor.wallet === 'string') return { wallet: receipt.anchor.wallet, src: 'anchor.wallet' };
  if (receiptPath && receiptPath !== '-') {
    const stem = path.basename(receiptPath).replace(/\.json$/i, '');
    try { if (Buffer.from(bs58.decode(stem)).length === 32) return { wallet: stem, src: 'filename' }; } catch (_) {}
  }
  return { wallet: undefined, src: 'none' };
}

// Authenticity for a cNFT receipt: Ed25519-verify the hex signature over the
// reconstructed compact-JSON payload against the trusted key. There is no keccak
// leaf to recompute - tamper-evidence is the signature itself: any change to a
// signed field (incl. wallet) invalidates it.
function verifyCnft(receipt, trustedPubkey, wallet) {
  const out = { mode: 'cnft', signature_valid: false, errors: [] };
  const a = (receipt && receipt.anchor) || {};
  out.wallet = wallet;
  if (!wallet) {
    out.errors.push('cNFT receipt: wallet unknown - it is part of the signed payload but not in the anchor block. Pass --wallet <addr> or name the file <wallet>.json.');
    return out;
  }
  const embedded = a.verify_pubkey;
  if (embedded && embedded !== trustedPubkey) {
    out.errors.push(`anchor.verify_pubkey ${embedded} != trusted key ${trustedPubkey}`);
    return out;
  }
  const sigHex = String(a.signature || '').toLowerCase().replace(/^0x/, '');
  if (!sigHex) { out.errors.push('missing anchor.signature'); return out; }
  if (!/^[0-9a-f]+$/.test(sigHex) || sigHex.length !== 128) {
    out.errors.push(`anchor.signature must be 64 hex bytes (got ${sigHex.length / 2 | 0})`);
    return out;
  }
  const sig = Buffer.from(sigHex, 'hex');
  const msg = cnftSignedPayload(a, wallet);
  out.signed_payload = msg.toString('utf8');
  let pk;
  try { pk = b58decode(trustedPubkey); }
  catch (e) { out.errors.push('trusted pubkey not base58: ' + e.message); return out; }
  try {
    out.signature_valid = nacl.sign.detached.verify(
      new Uint8Array(msg), new Uint8Array(sig), new Uint8Array(pk));
  } catch (e) { out.errors.push('signature check error: ' + e.message); return out; }
  if (!out.signature_valid) {
    out.errors.push('signature not valid for the trusted key (payload tampered, or wrong --wallet / --pubkey)');
  }
  out.valid = out.signature_valid && out.errors.length === 0;
  out.trusted_pubkey = trustedPubkey;
  return out;
}

// API responses nest the receipt under `twzrd_receipt` (GET /v1/intel/trust,
// GET /v1/receipts/example); accept them directly so piped curl output verifies.
function unwrapReceipt(obj) {
  if (obj && typeof obj === 'object' && !obj.preimage && !obj.anchor
      && obj.twzrd_receipt && typeof obj.twzrd_receipt === 'object') {
    return obj.twzrd_receipt;
  }
  return obj;
}

async function main() {
  const args = process.argv.slice(2);
  const HELP = `twzrd-receipt-verifier -- offline verifier for TWZRD receipts (Ed25519)

Verifies, with NO trust in TWZRD's servers or code, that a receipt was authored by
TWZRD's published Ed25519 key and was not tampered with. Auto-detects two families:
  - AO-Receipt V5/V6/V7 (trust-API): keccak256 leaf, signed by ${'Ak5SQwH...'} (current v2 key, default fetch; legacy v1 keys verify-only)
  - cNFT Receipt (genesis anchor): compact-JSON payload, signed by ${DEFAULT_CNFT_PUBKEY.slice(0, 7)}... (built-in)

usage:
  twzrd-receipt-verifier <receipt.json|-> [--pubkey KEY] [--fetch-key] [--wallet ADDR] [--base-url URL] [--max-age SECS] [--self-test]

arguments:
  <receipt.json>   path to the receipt JSON, or "-" to read from stdin
  --pubkey KEY     trust this base58 Ed25519 pubkey (out-of-band) instead of fetching/built-in
  --fetch-key      (cNFT only) fetch the signing key from the published well-known descriptor
                   (--base-url or ${DEFAULT_CNFT_BASE_URL}) instead of the built-in copy. Trades
                   package-trust for domain/TLS-trust; default stays built-in (no network).
  --wallet ADDR    (cNFT only) the leaf-owner wallet, which is part of the signed payload but
                   not stored in the anchor block. Inferred from a <wallet>.json filename if omitted.
  --base-url URL   where to fetch the key: trust-API default ${DEFAULT_BASE_URL}; cNFT (--fetch-key)
                   default ${DEFAULT_CNFT_BASE_URL}
  --max-age SECS   replay-resistance policy: reject if the receipt's timestamp (preimage.timestamp_unix
                   for trust-API, anchor.minted_at for cNFT) is older than SECS, OR is missing.
                   Crypto is time-independent; this is opt-in relying-party policy.
  --self-test      additionally confirm a tampered copy FAILS (proves the check works)
  -h, --help       show this help

exit code: 0 = VALID, 1 = INVALID / error
trust-API key source: ${DEFAULT_BASE_URL}/.well-known/x402
cNFT key source:      ${DEFAULT_CNFT_BASE_URL}/v1/receipts/pubkey`;
  if (args.includes('-h') || args.includes('--help')) { console.log(HELP); process.exit(0); }
  if (args.length === 0) {
    console.error('usage: twzrd-receipt-verifier <receipt.json|-> [--pubkey KEY] [--fetch-key] [--wallet ADDR] [--base-url URL] [--max-age SECS] [--self-test]');
    console.error('       twzrd-receipt-verifier --help');
    process.exit(1);
  }
  const receiptArg = args[0];
  const getOpt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
  const selfTest = args.includes('--self-test');
  const baseUrl = getOpt('--base-url') || DEFAULT_BASE_URL;
  const maxAgeArg = getOpt('--max-age');
  const maxAge = maxAgeArg ? parseInt(maxAgeArg, 10) : 0;  // 0 = freshness check off (opt-in policy)

  const raw = receiptArg === '-' ? fs.readFileSync(0, 'utf8') : fs.readFileSync(receiptArg, 'utf8');
  const receipt = unwrapReceipt(JSON.parse(raw));

  // ── cNFT (Bubblegum anchor) receipt: Ed25519 over compact JSON, no keccak leaf ──
  if (isCnftReceipt(receipt)) {
    let trusted = getOpt('--pubkey'), keySrc;
    if (trusted) {
      keySrc = '--pubkey (out-of-band)';
    } else if (args.includes('--fetch-key')) {
      const fetchBase = getOpt('--base-url') || DEFAULT_CNFT_BASE_URL;
      trusted = await fetchCnftPubkey(fetchBase);
      keySrc = `fetched from ${fetchBase}`;
    } else {
      trusted = DEFAULT_CNFT_PUBKEY;
      keySrc = 'built-in genesis authority';
    }
    const { wallet, src: walletSrc } = resolveWallet({
      explicitWallet: getOpt('--wallet'), receipt, receiptPath: receiptArg,
    });
    console.log(`mode             : cNFT (Bubblegum anchor)`);
    console.log(`trusted pubkey   : ${trusted}  [source: ${keySrc}]`);
    console.log(`wallet           : ${wallet || '(unknown)'}  [source: ${walletSrc}]`);

    const res = verifyCnft(receipt, trusted, wallet);
    res.errors = res.errors || [];

    // Opt-in freshness gate (anchor.minted_at). cNFT receipts are long-lived by
    // design, so this is rarely useful, but kept for parity with the trust-API path.
    if (maxAge > 0) {
      const ts = receipt.anchor ? Number(receipt.anchor.minted_at) : NaN;
      if (!Number.isFinite(ts) || ts <= 0) {
        res.errors.push(`--max-age ${maxAge}s set but anchor has no valid minted_at`);
        res.valid = false;
      } else {
        const now = Math.floor(Date.now() / 1000);
        if (ts > now + DEFAULT_MAX_FUTURE_SKEW_SECONDS) {
          res.errors.push(
            `receipt timestamp in the future (ts=${ts} > now+skew=${now + DEFAULT_MAX_FUTURE_SKEW_SECONDS})`,
          );
          res.valid = false;
        }
        const age = Math.abs(now - ts);
        if (age > maxAge) { res.errors.push(`receipt too old (age ${age}s > --max-age ${maxAge}s)`); res.valid = false; }
      }
    }

    console.log(`signature_valid  : ${res.signature_valid}`);
    res.errors.forEach((e) => console.log('  - ' + e));
    let ok = !!res.valid;
    console.log(`RESULT           : ${ok ? 'VALID (TWZRD-authored, untampered)' : 'INVALID'}`);
    if (ok) console.log('                   verified with the same library TWZRD uses internally (npm: twzrd-receipt-verifier)');

    if (selfTest) {
      const tampered = unwrapReceipt(JSON.parse(raw));
      tampered.anchor = tampered.anchor || {};
      tampered.anchor.score_at_mint = (Number(tampered.anchor.score_at_mint) || 0) + 1;
      const t = verifyCnft(tampered, trusted, wallet);
      const passed = !t.valid;
      console.log(`self-test (tampered score must FAIL): ${passed ? 'PASS' : 'BROKEN'}`);
      ok = ok && passed;
    }
    process.exit(ok ? 0 : 1);
  }

  // ── trust-API receipt (V5/V6/V7): keccak256 leaf, signed over the leaf bytes ──
  // keccak self-test: refuse to run with a broken hash backend
  if (keccak256('') !== KECCAK_EMPTY) { console.error('FATAL: keccak256 backend is wrong'); process.exit(1); }

  let trusted = getOpt('--pubkey'), src;
  if (trusted) { src = '--pubkey (out-of-band)'; }
  else { trusted = await fetchPublishedPubkey(baseUrl); src = baseUrl + '/.well-known/x402'; }
  console.log(`mode             : AO-Receipt (trust-API)`);
  console.log(`trusted pubkey   : ${trusted}  [source: ${src}]`);

  // Freshness + future-skew live inside verify() for lockstep with Python
  // verify_receipt(..., max_age_seconds=...).
  const res = verify(receipt, trusted, maxAge > 0 ? { maxAgeSeconds: maxAge } : undefined);

  console.log(`leaf_valid       : ${res.leaf_valid}`);
  console.log(`signature_valid  : ${res.signature_valid}`);
  res.errors.forEach((e) => console.log('  - ' + e));
  let ok = !!res.valid;
  console.log(`RESULT           : ${ok ? 'VALID (TWZRD-authored, untampered)' : 'INVALID'}`);
  if (ok) console.log('                   verified with the same library TWZRD uses internally (npm: twzrd-receipt-verifier)');
  // BOUND vs FRESHNESS card (parity with the Python verifier, #1992). "VALID"
  // above attests the leaf-bound fields. On V6 the freshness triple is JSON-only
  // and editable without breaking the signature; on V7 it is bound into the leaf.
  // The card says which is which - saying so is not optional.
  console.log(formatBoundFreshnessCard(receipt, res));
  console.log(formatTrustedBits(receipt, res));

  if (selfTest) {
    const tampered = unwrapReceipt(JSON.parse(raw));
    tampered.preimage = tampered.preimage || {};
    tampered.preimage.score = (tampered.preimage.score || 0) + 1;
    const t = verify(tampered, trusted);
    const passed = !t.valid;
    console.log(`self-test (tampered score must FAIL): ${passed ? 'PASS' : 'BROKEN'}`);
    ok = ok && passed;
  }

  process.exit(ok ? 0 : 1);
}

// Export the pure verifiers for tests / programmatic use. Only run the CLI when
// invoked directly (so `require()` from the test suite does not trigger main()).
module.exports = {
  REPUTATION_V7_DOMAIN, canonicalFreshnessV7,
  verify, recomputeLeaf,
  verifyCnft, cnftSignedPayload, isCnftReceipt, resolveWallet,
  fetchCnftPubkey,
  DEFAULT_CNFT_PUBKEY, DEFAULT_CNFT_BASE_URL, CNFT_SIGNED_FIELDS,
  CURRENT_RECEIPT_SIGNING_KEY_ID, LEGACY_RECEIPT_SIGNING_KEY_ID,
  CURRENT_RECEIPT_PUBKEY, LEGACY_RECEIPT_PUBKEYS,
  KNOWN_RECEIPT_DOMAINS,
  REPUTATION_V5_DOMAIN, ATTENTION_V5_DOMAIN, REPUTATION_V6_DOMAIN, ATTENTION_V6_DOMAIN,
  FRESHNESS_UNAUTHENTICATED_FIELDS, REPUTATION_PROVENANCE_FIELDS, unauthenticatedFields,
  hashedLeafBinding, classifyLeafBinding,
  V5_PREFIX_BOUND_FIELDS, boundFieldNames, freshnessFieldNames, cardVerdict,
  formatBoundFreshnessCard, formatTrustedBits,
  verifyReadiness, recomputeReadinessLeaf, isReadinessReceipt,
  READINESS_V1_DOMAIN, KNOWN_READINESS_DOMAINS, READINESS_BASIS,
  LEAF_DIGEST_LEN, PUBKEY_LEN, SIGNATURE_LEN,
  MAX_AGENT_ID_UTF8, MAX_PROVENANCE_STR_UTF8, DEFAULT_MAX_FUTURE_SKEW_SECONDS,
  // Was missing from exports, so the proof-depth guard test read `undefined`
  // and threw RangeError instead of exercising the guard.
  MAX_PROOF_DEPTH,
  MAX_READINESS_STR_UTF8, MAX_READINESS_LIST_ITEMS,
};

if (require.main === module) {
  main().catch((e) => { console.error('error:', e.message); process.exit(1); });
}
