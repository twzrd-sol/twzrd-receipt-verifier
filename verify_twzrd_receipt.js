#!/usr/bin/env node
/*
 * Standalone offline verifier for TWZRD AO-Receipt V5 (Node).
 *
 * Verifies, with NO trust in TWZRD's servers or codebase, that a receipt was
 * authored by TWZRD's published Ed25519 key and was not tampered with:
 *   1. TAMPER-EVIDENCE - recompute the keccak256 leaf from the preimage,
 *      confirm it equals receipt.leaf.
 *   2. AUTHENTICITY    - verify the Ed25519 signature over the leaf bytes
 *      against TWZRD's PUBLISHED public key (you supply / fetch it).
 *
 * Crypto comes from audited libs (tweetnacl = ref Ed25519, js-sha3 = Keccak),
 * not from this script. base58 + the TWZRD byte layout are the only logic here.
 *
 *   npm install tweetnacl js-sha3 bs58
 *
 *   node verify_twzrd_receipt.js receipt.json
 *   node verify_twzrd_receipt.js receipt.json --pubkey 9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf
 *   cat receipt.json | node verify_twzrd_receipt.js -            # stdin
 *   node verify_twzrd_receipt.js receipt.json --self-test        # tamper must fail
 *
 * Exit code 0 = VALID, 1 = INVALID / error.
 */
'use strict';

const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const nacl = require('tweetnacl');
const { keccak256 } = require('js-sha3');
const bs58 = require('bs58');

const DEFAULT_BASE_URL = 'https://intel.twzrd.xyz';
const KECCAK_EMPTY = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

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

function recomputeLeaf(pre) {
  // Use the exact domain the receipt carries. V6 binds reputation_* into the leaf
  // (V5 left them unsigned/forgeable); a V6 receipt verified with V5 rules would
  // fail on a legitimate receipt, so the block is appended whenever domain is _V6.
  const dom = String(pre.domain || '').toUpperCase();
  const isV6 = dom.includes('_V6');
  const isAttention = dom.includes('ATTENTION');
  const domainStr = isAttention
    ? (isV6 ? 'TWZRD:AO_ATTENTION_RECEIPT_V6' : 'TWZRD:AO_ATTENTION_RECEIPT_V5')
    : (isV6 ? 'TWZRD:AO_REPUTATION_RECEIPT_V6' : 'TWZRD:AO_REPUTATION_RECEIPT_V5');
  const domain = Buffer.from(domainStr, 'ascii');
  const score = isAttention ? (pre.attention_score || 0) : (pre.score || 0);
  const agent = Buffer.from(pre.agent_id, 'utf8');
  const parts = [
    domain,
    u16le(agent.length), agent,
    u16le(score),
    u16le(pre.confidence_bps),
    u64le(pre.timestamp_unix),
    payer32(pre.payer),
    anchor32(pre.settlement_tx || pre.settlement_anchor),
  ];
  if (isV6) parts.push(encodeReputationBlockV6(pre));
  return Buffer.from(keccak256.arrayBuffer(Buffer.concat(parts)));
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

function verify(receipt, trustedPubkey) {
  const out = { leaf_valid: false, signature_valid: false, errors: [] };
  const pre = receipt.preimage || {};
  const leafHex = String(receipt.leaf || '').toLowerCase().replace(/^0x/, '');

  let recomputed;
  try { recomputed = recomputeLeaf(pre); }
  catch (e) { out.errors.push('could not recompute leaf: ' + e.message); return out; }
  out.recomputed_leaf = '0x' + recomputed.toString('hex');
  out.leaf_valid = recomputed.toString('hex') === leafHex;
  if (!out.leaf_valid) out.errors.push('leaf mismatch: preimage does not hash to receipt.leaf');

  const sig = receipt.signature;
  if (!sig) { out.errors.push('missing signature (unsigned receipts are rejected)'); return out; }

  const embedded = receipt.signing_pubkey;
  if (embedded && embedded !== trustedPubkey) {
    out.errors.push(`signing_pubkey ${embedded} != trusted published key ${trustedPubkey}`);
    return out;
  }

  try {
    out.signature_valid = nacl.sign.detached.verify(
      new Uint8Array(recomputed),
      new Uint8Array(b58decode(sig)),
      new Uint8Array(b58decode(trustedPubkey)),
    );
  } catch (e) { out.errors.push('signature check error: ' + e.message); return out; }
  if (!out.signature_valid) out.errors.push('signature not valid for the trusted published key');

  out.valid = out.leaf_valid && out.signature_valid && out.errors.length === 0;
  out.trusted_pubkey = trustedPubkey;
  return out;
}

async function main() {
  const args = process.argv.slice(2);
  const HELP = `twzrd-receipt-verifier -- offline verifier for TWZRD AO-Receipt V5 (Ed25519-signed keccak256 leaf)

Verifies, with NO trust in TWZRD's servers or code, that a receipt was authored by
TWZRD's published Ed25519 key and was not tampered with.

usage:
  twzrd-receipt-verifier <receipt.json|-> [--pubkey KEY] [--base-url URL] [--max-age SECS] [--self-test]

arguments:
  <receipt.json>   path to the receipt JSON, or "-" to read from stdin
  --pubkey KEY     trust this base58 Ed25519 pubkey (out-of-band) instead of fetching it
  --base-url URL   where to fetch the published key (default: ${DEFAULT_BASE_URL})
  --max-age SECS   replay-resistance policy: reject if preimage.timestamp_unix is older than
                   SECS, OR if the receipt carries no valid timestamp. Crypto (leaf+sig) is
                   time-independent; this is opt-in relying-party policy.
  --self-test      additionally confirm a tampered copy FAILS (proves the check works)
  -h, --help       show this help

exit code: 0 = VALID, 1 = INVALID / error
key source: ${DEFAULT_BASE_URL}/.well-known/x402`;
  if (args.includes('-h') || args.includes('--help')) { console.log(HELP); process.exit(0); }
  if (args.length === 0) {
    console.error('usage: twzrd-receipt-verifier <receipt.json|-> [--pubkey KEY] [--base-url URL] [--max-age SECS] [--self-test]');
    console.error('       twzrd-receipt-verifier --help');
    process.exit(1);
  }
  const receiptArg = args[0];
  const getOpt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
  const selfTest = args.includes('--self-test');
  const baseUrl = getOpt('--base-url') || DEFAULT_BASE_URL;
  const maxAgeArg = getOpt('--max-age');
  const maxAge = maxAgeArg ? parseInt(maxAgeArg, 10) : 0;  // 0 = freshness check off (opt-in policy)

  // keccak self-test: refuse to run with a broken hash backend
  if (keccak256('') !== KECCAK_EMPTY) { console.error('FATAL: keccak256 backend is wrong'); process.exit(1); }

  const raw = receiptArg === '-' ? fs.readFileSync(0, 'utf8') : fs.readFileSync(receiptArg, 'utf8');
  const receipt = JSON.parse(raw);

  let trusted = getOpt('--pubkey'), src;
  if (trusted) { src = '--pubkey (out-of-band)'; }
  else { trusted = await fetchPublishedPubkey(baseUrl); src = baseUrl + '/.well-known/x402'; }
  console.log(`trusted pubkey: ${trusted}  [source: ${src}]`);

  const res = verify(receipt, trusted);

  // Opt-in replay-resistance freshness gate. Crypto (leaf+sig) is time-independent; this is
  // relying-party policy. A receipt with missing/zero timestamp_unix is REJECTED when
  // --max-age is set (no silent bypass) — mirrors the Python verifier (#720).
  if (maxAge > 0) {
    res.errors = res.errors || [];
    const ts = receipt && receipt.preimage ? Number(receipt.preimage.timestamp_unix) : NaN;
    if (!Number.isFinite(ts) || ts <= 0) {
      res.errors.push(`--max-age ${maxAge}s set but receipt has no valid timestamp_unix`);
      res.valid = false;
    } else {
      const age = Math.abs(Math.floor(Date.now() / 1000) - ts);
      if (age > maxAge) {
        res.errors.push(`receipt too old (age ${age}s > --max-age ${maxAge}s)`);
        res.valid = false;
      }
    }
  }

  console.log(`leaf_valid       : ${res.leaf_valid}`);
  console.log(`signature_valid  : ${res.signature_valid}`);
  res.errors.forEach((e) => console.log('  - ' + e));
  let ok = !!res.valid;
  console.log(`RESULT           : ${ok ? 'VALID (TWZRD-authored, untampered)' : 'INVALID'}`);

  if (selfTest) {
    const tampered = JSON.parse(raw);
    tampered.preimage = tampered.preimage || {};
    tampered.preimage.score = (tampered.preimage.score || 0) + 1;
    const t = verify(tampered, trusted);
    const passed = !t.valid;
    console.log(`self-test (tampered score must FAIL): ${passed ? 'PASS' : 'BROKEN'}`);
    ok = ok && passed;
  }

  process.exit(ok ? 0 : 1);
}

main().catch((e) => { console.error('error:', e.message); process.exit(1); });
