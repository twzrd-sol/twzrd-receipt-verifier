# TWZRD Receipt Verifier (standalone)

Verify a TWZRD **AO-Receipt V5** offline, trusting **nothing from TWZRD's servers
or codebase** - only the receipt, TWZRD's published public key, and two
widely-audited crypto libraries.

A TWZRD trust receipt has two layers:

1. **Tamper-evidence** - a `keccak256` leaf over the receipt's preimage fields.
2. **Authenticity** - an **Ed25519 signature** over the leaf bytes, made with
   TWZRD's dedicated receipt-signing key.

This tool recomputes the leaf **and** checks the signature against the published
key. If it says `VALID`, the receipt was authored by TWZRD and was not altered.
Unsigned, wrong-key, or tampered receipts fail.

## Where this fits: the agent trust loop

This verifier is the **last step** of the x402 trust rail an agent runs before and
after it spends:

1. **Discover** a model/provider - [`wzrd-client`](https://pypi.org/project/wzrd-client/) (PyPI) or [`@wzrd_sol/sdk`](https://www.npmjs.com/package/@wzrd_sol/sdk) (npm)
2. **Preflight** the seller wallet, free - `POST https://intel.twzrd.xyz/v1/intel/preflight` (or MCP `get_readiness_card_tool`)
3. **Pay** with a signed receipt - `GET https://intel.twzrd.xyz/v1/intel/trust/{seller}` (0.05 USDC, x402)
4. **Verify** the receipt offline - **this package** (trust nothing but the bytes + the public key)

```bash
# zero-install: verify a receipt straight from the published package
npx twzrd-receipt-verifier receipt.json --pubkey 9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf

# replay-resistance (opt-in): reject receipts older than 60s — and reject any with no timestamp
npx twzrd-receipt-verifier receipt.json --pubkey 9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf --max-age 60
```

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

## Get a receipt to verify

Any TWZRD V5 receipt works. To mint a fresh one, pay the trust endpoint (x402,
0.05 USDC on Solana mainnet) - e.g. via AgentCash:

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

Source: [packages/twzrd-agent-intel/verifier](https://github.com/twzrd-sol/wzrd-final/tree/main/packages/twzrd-agent-intel/verifier)

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
code. Swap the libraries for your own if you prefer - the byte layout above is the
whole spec.
