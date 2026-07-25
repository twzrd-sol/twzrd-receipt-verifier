#!/usr/bin/env node
/*
 * Standalone offline verifier for TWZRD receipts (Node). Two receipt families,
 * auto-detected:
 *
 *   A. AO-Receipt V5/V6 (trust-API)  - keccak256 leaf over a packed preimage,
 *      Ed25519-signed over the leaf bytes by the receipt key (9V6Pn19...).
 *      Shape: { preimage, leaf, signature, signing_pubkey }.
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
 *   node verify_twzrd_receipt.js receipt.json --pubkey 9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf
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
const KECCAK_EMPTY = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
// Genesis cNFT receipt authority (airship). Baked in as the most paranoid form of
// out-of-band pinning: the key ships in this audited package, never fetched live.
// Override with --pubkey, or fetch the published copy with --fetch-key (cross-check).
// Matches `verify_pubkey` in every genesis anchor and the verified creator on every
// cNFT in tree 8QFdTqBkSeyuvp47dXdpwfWzXTuYSbAC64oT4soPGnXS.
const DEFAULT_CNFT_PUBKEY = '2ELSDxLkb7dYrN6EUG69tNtULAq4Fo7WPvXyrZPmuFif';
// Where --fetch-key looks for the published cNFT key descriptor.
const DEFAULT_CNFT_BASE_URL = 'https://api.twzrd.xyz';

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
  - AO-Receipt V5/V6 (trust-API): keccak256 leaf, signed by ${'9V6Pn19...'} (default fetch)
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
        const age = Math.abs(Math.floor(Date.now() / 1000) - ts);
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

  // ── trust-API receipt (V5/V6): keccak256 leaf, signed over the leaf bytes ──
  // keccak self-test: refuse to run with a broken hash backend
  if (keccak256('') !== KECCAK_EMPTY) { console.error('FATAL: keccak256 backend is wrong'); process.exit(1); }

  let trusted = getOpt('--pubkey'), src;
  if (trusted) { src = '--pubkey (out-of-band)'; }
  else { trusted = await fetchPublishedPubkey(baseUrl); src = baseUrl + '/.well-known/x402'; }
  console.log(`mode             : AO-Receipt (trust-API)`);
  console.log(`trusted pubkey   : ${trusted}  [source: ${src}]`);

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
  if (ok) console.log('                   verified with the same library TWZRD uses internally (npm: twzrd-receipt-verifier)');

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
  verify, recomputeLeaf,
  verifyCnft, cnftSignedPayload, isCnftReceipt, resolveWallet,
  fetchCnftPubkey,
  DEFAULT_CNFT_PUBKEY, DEFAULT_CNFT_BASE_URL, CNFT_SIGNED_FIELDS,
};

if (require.main === module) {
  main().catch((e) => { console.error('error:', e.message); process.exit(1); });
}
