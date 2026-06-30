# TWZRD Receipt Verifier (standalone)

[![npm version](https://img.shields.io/npm/v/twzrd-receipt-verifier)](https://www.npmjs.com/package/twzrd-receipt-verifier)
[![npm downloads](https://img.shields.io/npm/dw/twzrd-receipt-verifier)](https://www.npmjs.com/package/twzrd-receipt-verifier)
[![PyPI version](https://img.shields.io/pypi/v/twzrd-receipt-verifier)](https://pypi.org/project/twzrd-receipt-verifier/)
[![license](https://img.shields.io/npm/l/twzrd-receipt-verifier)](LICENSE)
[![node](https://img.shields.io/node/v/twzrd-receipt-verifier)](https://nodejs.org)
![platform](https://img.shields.io/badge/platform-Node%20%7C%20Python-blue)

> **Zero-trust, offline-first. No API calls. No servers. No TWZRD code you didn't read.**

**Hero quickstart — verify a receipt in one command:**

```bash
# AO-Receipt (trust-API): works immediately on any receipt JSON
npx twzrd-receipt-verifier receipt.json --self-test

# cNFT Receipt (genesis): fetch + verify a genesis compressed-NFT receipt
W=zoz7neLHXoaLwNBuckSqNqaMsacpqJsphtFuNNpQyt3
curl -s https://twzrd.xyz/r/$W.json | npx twzrd-receipt-verifier -
```

---

Verify a TWZRD receipt offline, trusting **nothing from TWZRD's servers or
codebase** — only the receipt, TWZRD's published public key, and two
widely-audited crypto libraries. The verifier **auto-detects** two receipt
families:

| Family | What it is | Scheme | Signing key |
|--------|-----------|--------|-------------|
| **AO-Receipt V5/V6** | trust-API receipts from `intel.twzrd.xyz` | `keccak256` leaf over a packed preimage, Ed25519 over the leaf bytes | `9V6Pn19...` (fetched/pinned) |
| **cNFT Receipt** | the 95k genesis compressed-NFT receipts | Ed25519 **directly** over a compact-JSON payload (no leaf), hex sig | `2ELSDx...` (built-in) |

For V5/V6 the verifier reads the domain the receipt carries and applies the
matching leaf rules (V6 binds the `reputation_*` provenance fields into the signed
leaf; V5 left them unsigned). For cNFT receipts there is no leaf — tamper-evidence
**is** the signature: any change to a signed field (including the wallet)
invalidates it.

If it says `VALID`, the receipt was authored by TWZRD and was not altered.
Unsigned, wrong-key, wrong-wallet, or tampered receipts fail.

## Why this exists

TWZRD is the **pre-spend trust gate for agents paying over x402**. Every agent
payment should go through a before/during/after trust loop:

1. **Preflight** — is this counterparty safe to pay?
2. **Pay** — settle on-chain with a signed receipt.
3. **Verify** — trust-but-verify every receipt offline.

This verifier is step 3 — the **credibility anchor** that lets any agent prove it
actually paid, and any receiver confirm the payment was legitimate, without
trusting TWZRD's live infrastructure. It's the lowest-friction entry point into
the TWZRD trust layer: MIT-licensed, zero-install, offline-first.

### Use cases

- **Agent payment verification** — confirm every x402 payment produced a valid
  TWZRD receipt before trusting the response.
- **Preflight integration** — run `--self-test` in CI to prove the verification
  pipeline works before wiring it into a payment agent.
- **Solana AA paymaster / relay** — verify receipts as part of a fee-payer
  sponsorship flow (proof that the payer-slot semantics were honored).
- **Streaming micropay proofs** — batch-verify receipt chains for recurring or
  streaming payment models.
- **Offline audit** — verify receipts on an air-gapped machine with a pinned key.
  No network required.

## Where this fits: the agent trust loop

This verifier is the **last step** of the x402 trust rail an agent runs before and
after it spends:

1. **Discover** a model/provider — [`wzrd-client`](https://pypi.org/project/wzrd-client/) (PyPI) or [`@wzrd_sol/sdk`](https://www.npmjs.com/package/@wzrd_sol/sdk) (npm)
2. **Preflight** the seller wallet, free — `POST https://intel.twzrd.xyz/v1/intel/preflight` (or MCP `get_readiness_card_tool`)
3. **Pay** with a signed receipt — `GET https://intel.twzrd.xyz/v1/intel/trust/{seller}` (0.05 USDC, x402)
4. **Verify** the receipt offline — **this package** (trust nothing but the bytes + the public key)

```bash
# zero-install: verify a receipt straight from the published package
npx twzrd-receipt-verifier receipt.json --pubkey 9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf

# replay-resistance (opt-in): reject receipts older than 60s — and reject any with no timestamp
npx twzrd-receipt-verifier receipt.json --pubkey 9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf --max-age 60
```

### 🔐 Paranoid mode

Pin the key out-of-band with `--pubkey` instead of fetching it. You never trust
the live endpoint to tell you which key to trust:

```bash
npx twzrd-receipt-verifier receipt.json --pubkey 9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf
```

For cNFT receipts, the genesis signing key (`2ELSDx...`) is **baked into the
package** — no network fetch by default. Use `--fetch-key` only to cross-check
against the live published descriptor.

### 🛡️ Audited dependencies only

The verifier uses exactly three audited crypto libraries and nothing else:

- [`tweetnacl`](https://github.com/dchest/tweetnacl-js) — reference Ed25519
- [`js-sha3`](https://github.com/emn178/js-sha3) — Keccak-256
- [`bs58`](https://github.com/cryptocoinjs/bs58) — base58 encoding

No build step. No bundler. No framework. Just 457 lines of readable Node.js you
can audit in 10 minutes.

## The published signing key

| field | value |
|-------|-------|
| algorithm | `ed25519` |
| key_id | `twzrd-receipt-ed25519-v1` |
| public key (base58) | `9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf` |

Also published, machine-readable, at:
- `https://intel.twzrd.xyz/.well-known/x402` → `receipt.signature.public_key`
- `https://intel.twzrd.xyz/openapi.json` → `x402.receipt.signature.public_key`
- the MCP card `agent-intel-mcp-card.json` → `receipt_signing.public_key`

> **Most paranoid mode:** pin the key out-of-band with `--pubkey` instead of
> fetching it, so you never trust the live endpoint to tell you which key to trust.

## cNFT Receipts (the 95k genesis receipts)

Every genesis receipt is a compressed NFT on Solana mainnet (tree
`8QFdTqBkSeyuvp47dXdpwfWzXTuYSbAC64oT4soPGnXS`, verified creator `2ELSDx...`). Its
at-mint snapshot is published as a signed `anchor` block in the cNFT metadata,
served at `https://twzrd.xyz/r/<wallet>.json`:

```json
{
  "anchor": {
    "tier_at_mint": "Platinum",
    "score_at_mint": 255,
    "verified_tx": "<solana settlement signature>",
    "behavior_proof": "<sha256 hex>",
    "minted_at": 1782415336,
    "signature": "<128-hex Ed25519 sig>",
    "verify_pubkey": "2ELSDxLkb7dYrN6EUG69tNtULAq4Fo7WPvXyrZPmuFif"
  },
  "live": { "...": "current decayed reputation (NOT signed)" }
}
```

The signed payload is the compact JSON `{wallet, tier_at_mint, score_at_mint,
verified_tx, behavior_proof, minted_at}` (exact key order). The `wallet` is the
first signed field but is **not** stored in the anchor — it is the `<wallet>.json`
filename / the cNFT leaf owner — so pass `--wallet` or keep the filename. The
signing key (`2ELSDx...`) is **built in** to the verifier (pinned in the audited
package); override with `--pubkey`, or fetch the published copy with `--fetch-key`.

```bash
# fetch a receipt and verify it (wallet inferred from the filename, key built-in)
W=zoz7neLHXoaLwNBuckSqNqaMsacpqJsphtFuNNpQyt3
curl -s https://twzrd.xyz/r/$W.json -o $W.json
npx twzrd-receipt-verifier $W.json --self-test

# or pass the wallet explicitly (e.g. when piping from stdin)
npx twzrd-receipt-verifier anchor.json --wallet $W

# fetch the key from the published descriptor instead of the built-in copy
# (cross-check, or pin to whatever the live domain publishes)
npx twzrd-receipt-verifier $W.json --fetch-key
```

The key is published, machine-readable, at `https://api.twzrd.xyz/v1/receipts/pubkey`
(and `https://twzrd.xyz/.well-known/twzrd-receipt-pubkey`) with the full signing spec
(`public_key`, `signed_fields`, `scheme`, `tree`). It must equal the built-in key **and**
the on-chain verified creator of every cNFT in the tree — three independent sources.

```
mode             : cNFT (Bubblegum anchor)
trusted pubkey   : 2ELSDxLkb7dYrN6EUG69tNtULAq4Fo7WPvXyrZPmuFif  [source: built-in genesis authority]
wallet           : zoz7neLHXoaLwNBuckSqNqaMsacpqJsphtFuNNpQyt3  [source: filename]
signature_valid  : true
RESULT           : VALID (TWZRD-authored, untampered)
```

Only the `anchor` block is signed. The `live` block (current decayed reputation)
is informational and intentionally NOT covered by the signature. For full on-chain
binding, confirm the cNFT exists in the genesis tree with verified creator
`2ELSDx` via any DAS provider (`getAsset` / `getAssetProof`); the signature alone
already proves `2ELSDx` authorship of the at-mint snapshot.

## Get a receipt to verify

Any TWZRD V5/v6 receipt works. To mint a fresh one, pay the trust endpoint
(x402, 0.05 USDC on Solana mainnet) with an x402 client that preserves TWZRD's
sponsored fee-payer slot semantics.

Current caveat (2026-06-23): `npx agentcash@latest fetch ...` is not a green
TWZRD paid-trust repro. It failed closed with `payment_invalid` /
`fee_payer_slot_already_signed`, and AgentCash balance stayed unchanged.

Known-bad compatibility command:

```bash
npx agentcash@latest fetch https://intel.twzrd.xyz/v1/intel/trust/<PUBKEY> > resp.json
# the receipt is the `twzrd_receipt` object in the response
```

The receipt object looks like:

```json
{
  "version": "v5",
  "leaf": "0x...",
  "preimage": { "domain": "TWZRD:AO_REPUTATION_RECEIPT_V5", "agent_id": "...", "score": 15, "...": "..." },
  "signature": "base58 ed25519 sig",
  "signing_pubkey": "9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf",
  "key_id": "twzrd-receipt-ed25519-v1",
  "signing_alg": "ed25519"
}
```

## Python

```bash
pip install twzrd-receipt-verifier   # PyPI; or: pip install pynacl pycryptodome for script-only use

# fetch the published key and verify:
twzrd-verify-receipt receipt.json
# or: python verify_twzrd_receipt.py receipt.json

# pin the key out-of-band (recommended):
python verify_twzrd_receipt.py receipt.json --pubkey 9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf

# also confirm a tampered copy FAILS:
twzrd-verify-receipt receipt.json --self-test

# replay-resistance (opt-in; same semantics as the npm CLI --max-age):
twzrd-verify-receipt receipt.json --max-age 300

# from stdin:
cat receipt.json | twzrd-verify-receipt -
```

Source: [twzrd-sol/twzrd-receipt-verifier](https://github.com/twzrd-sol/twzrd-receipt-verifier)

## Node

```bash
npm install                          # tweetnacl + js-sha3 + bs58

node verify_twzrd_receipt.js receipt.json
node verify_twzrd_receipt.js receipt.json --pubkey 9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf --self-test
cat receipt.json | node verify_twzrd_receipt.js -
```

Both exit `0` on `VALID`, `1` on `INVALID`.

## What it checks (and the exact layout)

The keccak256 leaf preimage is a strict little-endian, length-prefixed concat
(reproducible in any language):

```
domain            = "TWZRD:AO_REPUTATION_RECEIPT_V5"   (or ...ATTENTION... for attention receipts)
agent_id          = u16_le(len(utf8)) || utf8 bytes
score             = u16_le
confidence_bps    = u16_le
timestamp_unix    = u64_le
payer             = 32 bytes  (base58-decoded pubkey, or sha256(marker) for synthetic payers)
settlement_anchor = 32 bytes  (last 32 bytes of the utf-8 settlement_tx string, or 32 zero bytes)

leaf      = keccak256(domain || agent_id || score || confidence_bps || timestamp_unix || payer || settlement_anchor)
signature = Ed25519_sign(receipt_signing_key, leaf_bytes)
```

The verifier:
1. recomputes `leaf` from the preimage and compares it to `receipt.leaf`,
2. confirms `receipt.signing_pubkey` (if present) equals the trusted key,
3. verifies the Ed25519 `signature` over the 32 leaf bytes against the trusted key.

`VALID` requires all three. The `settlement_tx` in the preimage is an on-chain
Solana signature you can independently check for ground truth.

## Trust assumptions

You trust: the receipt you were given, the published public key (ideally pinned),
and the crypto libraries (`PyNaCl`/libsodium, `pycryptodome`; `tweetnacl`,
`js-sha3`). You do **not** trust TWZRD's API, database, or this repository's other
code. Swap the libraries for your own if you prefer — the byte layout above is the
whole spec.

## License

MIT — read the code, fork it, ship it. No strings attached.
