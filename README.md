# TWZRD Receipt Verifier (standalone)

**Verify a real TWZRD receipt in one command.** No wallet, no signup, no API key.
Copy-paste this and watch it print `VALID`:

```bash
W=zoz7neLHXoaLwNBuckSqNqaMsacpqJsphtFuNNpQyt3
curl -s https://twzrd.xyz/r/$W.json | npx twzrd-receipt-verifier - --wallet $W
```

```text
mode             : cNFT (Bubblegum anchor)
trusted pubkey   : 2ELSDxLkb7dYrN6EUG69tNtULAq4Fo7WPvXyrZPmuFif  [source: built-in genesis authority]
wallet           : zoz7neLHXoaLwNBuckSqNqaMsacpqJsphtFuNNpQyt3  [source: --wallet]
signature_valid  : true
RESULT           : VALID (TWZRD-authored, untampered)
                   verified with the same library TWZRD uses internally (npm: twzrd-receipt-verifier)
```

That output came from your machine, not ours. Nothing in the command trusts a
TWZRD server - it fetches bytes, then checks an Ed25519 signature against a
published key using audited crypto libraries.

> **`--wallet` is required when piping.** A cNFT receipt's wallet is inside the
> signed payload but not the anchor block, so it cannot be inferred from stdin.
> Save the file as `<wallet>.json` instead and the filename supplies it:
> `curl -s https://twzrd.xyz/r/$W.json -o $W.json && npx twzrd-receipt-verifier $W.json`

---

Verify a TWZRD receipt offline, trusting **nothing from TWZRD's servers or
codebase** - only the receipt, TWZRD's published public key, and two
widely-audited crypto libraries. The verifier **auto-detects** two receipt
families:

| Family | What it is | Scheme | Signing key |
|--------|-----------|--------|-------------|
| **AO-Receipt V5/V6/V7** | trust-API receipts from `intel.twzrd.xyz` (the live key issues V7 today; V5 and V6 still verify) | `keccak256` leaf over a packed preimage (V6 appends the `reputation_*` block; V7 wraps the V6 leaf with the freshness triple), Ed25519 over the leaf bytes | current v2 key (fetched/pinned); legacy v1 keys verify-only |
| **cNFT Receipt** | the 95k genesis compressed-NFT receipts | Ed25519 **directly** over a compact-JSON payload (no leaf), hex sig | `2ELSDx...` (built-in) |

For V5/V6/V7 the verifier reads the domain the receipt carries and applies the
matching leaf rules (V6 binds the `reputation_*` provenance fields into the signed
leaf; V5 left them unsigned; V7 - exact domain `TWZRD:AO_REPUTATION_RECEIPT_V7`,
reputation receipts only, there is no attention V7 - additionally binds the
freshness triple `recheck_after_unix` / `staleness_days` / `score_decay_model`
into the leaf, together with the rule `recheck_after_unix == timestamp_unix +
staleness_days * 86400`). For cNFT receipts there is no leaf - tamper-evidence
**is** the signature: any change to a signed field (including the wallet)
invalidates it.

If it says `VALID`, the receipt was authored by TWZRD and was not altered.
Unsigned, wrong-key, wrong-wallet, or tampered receipts fail.

Since 1.3.0 the package also verifies a third, deliberately separate artifact
class - the **AgentReadinessReceipt** - via the programmatic API only (see
[AgentReadinessReceipt V1](#agentreadinessreceipt-v1-endpoint-conformance-not-trust)
below). The CLI rejects it by design; that rejection is a feature, not a gap.

## Where this fits: the agent trust loop

This verifier is the **last step** of the x402 trust rail an agent runs before and
after it spends:

1. **Discover** callable x402 resources, free - `GET https://intel.twzrd.xyz/v1/intel/resources` (an HTTP route; not an MCP tool)
2. **Preflight** the seller wallet, free - `POST https://intel.twzrd.xyz/v1/intel/preflight` (or MCP `get_readiness_card_tool`)
3. **Pay** with a signed receipt - `GET https://intel.twzrd.xyz/v1/intel/trust/{seller}` (0.05 USDC, x402)
4. **Verify** the receipt offline - **this package** (trust nothing but the bytes + the public key)

```bash
# zero-install: verify a receipt straight from the published package
npx twzrd-receipt-verifier receipt.json --pubkey Ak5SQwHpuQAqU7ty7ZWX7qgF39A9yi72c22KNn8sHzvS

# replay-resistance (opt-in): reject receipts older than 60s — and reject any with no timestamp
npx twzrd-receipt-verifier receipt.json --pubkey Ak5SQwHpuQAqU7ty7ZWX7qgF39A9yi72c22KNn8sHzvS --max-age 60
```

## The published signing key

| field | value |
|-------|-------|
| algorithm | `ed25519` |
| key_id | `twzrd-receipt-ed25519-v2` |
| public key (base58) | `Ak5SQwHpuQAqU7ty7ZWX7qgF39A9yi72c22KNn8sHzvS` |

During the bounded rollout, `twzrd-receipt-ed25519-v1` and its published
legacy public keys remain accepted for verification only. New receipts are
always signed with v2; do not relabel a v1 receipt as v2.

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
first signed field but is **not** stored in the anchor - it is the `<wallet>.json`
filename / the cNFT leaf owner - so pass `--wallet` or keep the filename. The
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
the on-chain verified creator of every cNFT in the tree - three independent sources.

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

## AgentReadinessReceipt V1 (endpoint conformance, NOT trust)

An **AgentReadinessReceipt** attests one thing: *this URL was probed at
`as_of_unix` and this is what it did* - x402 discovery, unpaid-402 conformance,
wash screen on the resolved `payTo`s. It is **endpoint conformance observed at a
point in time, not a trust vouch**. That limit is machine-readable and signed:
`basis` is always `endpoint_conformance` and `not_a_trust_vouch` is always
`true`; a receipt claiming anything else does not verify. A `ready` verdict
means the mechanics conform and no negative signal was found - it does **not**
mean the seller is trustworthy.

Get one from `POST https://intel.twzrd.xyz/v1/intel/verify-endpoint` (x402,
USDC on Solana) - the receipt is the `receipt` object in the response. A
`not_ready` result is still delivered and still signed: the fee buys the
observation, never a pass.

Verify it programmatically (same package, same published key):

```js
const { verifyReadiness, isReadinessReceipt } = require('twzrd-receipt-verifier');

const receipt = require('./response.json').receipt; // from POST /v1/intel/verify-endpoint
if (!isReadinessReceipt(receipt)) throw new Error('not a readiness receipt');

const out = verifyReadiness(receipt, 'Ak5SQwHpuQAqU7ty7ZWX7qgF39A9yi72c22KNn8sHzvS');
console.log(out.valid);              // signature + leaf both check out
console.log(out.verdict);            // ready | warn | not_ready
console.log(out.ownership_proven);   // did the operator prove control of the origin?
console.log(out.past_recheck_after); // advisory staleness - see below
```

Pass `{ maxAgeSeconds: 3600 }` as the third argument to additionally reject
receipts whose `as_of_unix` is further than an hour from now.

`recomputeReadinessLeaf(preimage)` is also exported if you want to rebuild the
keccak256 leaf yourself byte-for-byte.

**Two verdict classes, only one is fatal.** Signature or leaf failures mean the
artifact is forged or tampered - `out.valid` is `false`, discard it.
`out.past_recheck_after === true` is **advisory**: readiness is perishable (an
endpoint can regress the minute after the probe), so every receipt carries a
verdict-driven `recheck_after_unix`. A genuine-but-stale card stays
cryptographically `valid`; your policy decides whether to demand a fresh one.

**Why the domains are disjoint - and must stay that way.** Readiness receipts
sign under `TWZRD:AGENT_READINESS_RECEIPT_V1`; paid trust receipts sign under
the `V5`/`V6` reputation/attention domains and the `V7` reputation domain
(`TWZRD:AO_REPUTATION_RECEIPT_V7`; no attention `V7` exists). Neither allowlist contains the
other, so a readiness receipt can **never** verify as paid trust intel through
`verify()`, and a trust receipt can never verify through `verifyReadiness()` -
both directions are asserted in the test suite. Without that split, a
conformance observation ("the endpoint's 402 works") could be laundered into a
trust claim ("this seller is safe to pay"), which the down-only screening
doctrine forbids. This is also why the CLI - a payment-receipt tool - rejects
readiness receipts on its domain allowlist instead of quietly accepting them.

## Get a receipt to verify

Free sample first — the signature is real, so this proves the whole verify path
without paying or holding a wallet:

```bash
curl -s https://intel.twzrd.xyz/v1/receipts/example -o sample.json
npx twzrd-receipt-verifier@^1.4.0 sample.json \
  --pubkey Ak5SQwHpuQAqU7ty7ZWX7qgF39A9yi72c22KNn8sHzvS
```

Live paid receipt: `GET https://intel.twzrd.xyz/v1/intel/trust/{pubkey}` (x402,
0.05 USDC on Solana mainnet) with any x402-capable client — the receipt is the
`twzrd_receipt` object in the response. Since 1.2.2 the verifier auto-unwraps
`twzrd_receipt`, so the raw API response verifies as-is.

This package is only the offline **verify** step of the trust loop. Free
preflight, merchant cards, and discovery live on the remote MCP —
`https://intel.twzrd.xyz/mcp` (no wallet; includes `twzrd_demo_gate`).

The receipt object (V7, which is what the free sample and the paid `/trust`
route issue today) looks like:

```json
{
  "version": "v7",
  "kind": "twzrd_reputation_receipt_v7",
  "leaf": "0x...",
  "preimage": { "domain": "TWZRD:AO_REPUTATION_RECEIPT_V7", "version": "v7", "agent_id": "...", "score": 15, "timestamp_unix": 1748736000, "staleness_days": 3, "recheck_after_unix": 1748995200, "score_decay_model": "...", "...": "..." },
  "signature": "base58 ed25519 sig",
  "signing_pubkey": "Ak5SQwHpuQAqU7ty7ZWX7qgF39A9yi72c22KNn8sHzvS",
  "key_id": "twzrd-receipt-ed25519-v2",
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
python verify_twzrd_receipt.py receipt.json --pubkey Ak5SQwHpuQAqU7ty7ZWX7qgF39A9yi72c22KNn8sHzvS

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
node verify_twzrd_receipt.js receipt.json --pubkey Ak5SQwHpuQAqU7ty7ZWX7qgF39A9yi72c22KNn8sHzvS --self-test
cat receipt.json | node verify_twzrd_receipt.js -
```

Both exit `0` on `VALID`, `1` on `INVALID`.

## What it checks (and the exact layout)

The keccak256 leaf preimage is a strict little-endian, length-prefixed concat
(reproducible in any language):

```
# --- V5 prefix (domains TWZRD:AO_REPUTATION_RECEIPT_V5 / TWZRD:AO_ATTENTION_RECEIPT_V5) ---
domain            = exact domain string bytes, no length prefix
agent_id          = u16_le(len(utf8)) || utf8 bytes
score             = u16_le   (attention_score for ATTENTION domains; one shared slot)
confidence_bps    = u16_le
timestamp_unix    = u64_le
payer             = 32 bytes  (base58-decoded pubkey if exactly 32 bytes, else sha256(utf8(payer)) for marker payers)
settlement_anchor = 32 bytes  (first truthy of settlement_tx, settlement_anchor as utf-8 TEXT: last 32 bytes,
                               zero-left-padded if shorter, or 32 zero bytes when absent)

leaf_v5   = keccak256(domain || agent_id || score || confidence_bps || timestamp_unix || payer || settlement_anchor)

# --- V6 (domains ..._RECEIPT_V6): the same prefix under the V6 domain bytes, then a reputation block appended.
#     Each field = 1-byte presence flag (0x00 for null, else 0x01 || value); "" is present, distinct from null.
reputation_block  = flag || i64_le(reputation_score)
                 || flag || u16_le(reputation_confidence_bps)
                 || flag || u16_le(len) || utf8(reputation_score_version)
                 || flag || u64_le(reputation_feature_window_start_unix)
                 || flag || u16_le(len) || utf8(reputation_data_quality)
leaf_v6   = keccak256(domain_v6 || agent_id || score || confidence_bps || timestamp_unix || payer || settlement_anchor || reputation_block)

# --- V7 (domain TWZRD:AO_REPUTATION_RECEIPT_V7, reputation only): the V6 leaf is rebuilt under the V6 domain
#     bytes, then wrapped with the canonical freshness JSON (compact, keys sorted). Constraints checked before
#     hashing: recheck_after_unix == timestamp_unix + staleness_days * 86400; staleness_days <= 65535;
#     score_decay_model 1..256 printable ASCII; when settlement_tx is absent, settlement_anchor is HEX-decoded
#     and must be exactly 32 bytes (not the text rule above). The envelope must also carry
#     kind = "twzrd_reputation_receipt_v7", version = "v7" and preimage.version = "v7" (compared, not hashed).
fresh     = {"recheck_after_unix":N,"score_decay_model":"S","staleness_days":D}
leaf_v7   = keccak256("TWZRD:AO_REPUTATION_RECEIPT_V7" || leaf_v6 || u32_le(len(fresh)) || fresh)

signature = Ed25519_sign(receipt_signing_key, leaf_bytes)
```

The verifier:
1. recomputes `leaf` from the preimage and compares it to `receipt.leaf`,
2. confirms `receipt.signing_pubkey` (if present) equals the trusted key,
3. verifies the Ed25519 `signature` over the 32 leaf bytes against the trusted key.

`VALID` requires all three. The `settlement_tx` in the preimage is an on-chain
Solana signature you can independently check for ground truth.

## BOUND vs FRESHNESS: what `VALID` does and does not attest

For trust-API receipts, both CLIs print a per-field card after the verdict. `VALID`
covers ONLY the `BOUND` lines - the fields hashed into the keccak leaf that the
Ed25519 signature signs. On V5 and V6 receipts the freshness triple
(`recheck_after_unix`, `staleness_days`, `score_decay_model`) is JSON-only:
consumption policy hints that are NOT signature-bound and can be edited without
breaking the signature (on V5 the `reputation_*` fields are JSON-only too and
appear as `UNAUTH` lines). On V7 (exact domain `TWZRD:AO_REPUTATION_RECEIPT_V7`
only) the triple is hashed into the leaf:
`leaf = keccak256(V7_domain || v6_leaf || u32_le(len) || canonical_freshness_json)`,
where `canonical_freshness_json` is the compact, key-sorted JSON of the triple and
`recheck_after_unix` must equal `timestamp_unix + staleness_days * 86400`. So a V7
receipt that verifies `VALID` also attests the triple and its arithmetic relation to
the BOUND `timestamp_unix`; the FRESHNESS lines then read `covered by the V7 leaf
binding` instead. The card says which is which, so a relying party never mistakes
an unbound hint for an attested fact. A V6 card:

```
RESULT           : VALID (TWZRD-authored, untampered)
BOUND     domain   covered by Ed25519 over the signed payload
BOUND     agent_id   covered by Ed25519 over the signed payload
...
BOUND     reputation_score   covered by Ed25519 over the signed payload
FRESHNESS recheck_after_unix   present, NOT signature-bound; do not treat as proof
FRESHNESS staleness_days   present, NOT signature-bound; do not treat as proof
FRESHNESS score_decay_model   present, NOT signature-bound; do not treat as proof
VERDICT   valid-signature
trusted_due      : false
trusted_allow    : false
freshness_bound  : false
```

The same tail on a genuine V7 receipt (what the free sample at
`GET /v1/receipts/example` prints today):

```
FRESHNESS recheck_after_unix   covered by the V7 leaf binding
FRESHNESS staleness_days   covered by the V7 leaf binding
FRESHNESS score_decay_model   covered by the V7 leaf binding
VERDICT   valid-signature
trusted_due      : false
trusted_allow    : false
freshness_bound  : false
```

`trusted_due` / `trusted_allow` / `freshness_bound` are consumption bits, not a
readout of the receipt. Both CLIs print all three `false` unconditionally - on
V5, V6, genuine V7, on a spoofed `_V7` suffix (e.g. `_V6_V7`), and on a
V6-signed receipt whose domain was rewritten to the exact
`TWZRD:AO_REPUTATION_RECEIPT_V7` alike - and never read `trusted_*` from the
JSON. So `freshness_bound : false` under a V7 card does not contradict the
`covered by the V7 leaf binding` lines above it: the leaf binding is reported on
the FRESHNESS line, the consumption bit stays off. For trust-API receipts
`trusted_due` is never computed: `verify()` does not compare now to
`recheck_after_unix` (only the separate AgentReadinessReceipt path exposes an
advisory `past_recheck_after`, see above). Do not treat `VALID` as a trusted
recheck allow. If you need a freshness guarantee, enforce it yourself against
the BOUND `timestamp_unix` (e.g. `--max-age 300`); on V5/V6 never trust the
freshness triple, and on V7 trust it only behind a VALID verdict. In the
library result, a V6-signed receipt relabelled to the exact V7 domain still
returns `freshness_unauthenticated: false` and `unauthenticated_fields: []`
(classification is by domain string) while `valid` is `false`, so
`valid && freshness_unauthenticated === false` (JS) /
`res["valid"] and res["freshness_unauthenticated"] is False` (Python) is the
only binding signal; on the CLI that same condition is what switches the
FRESHNESS note to `covered by the V7 leaf binding`.

## Trust assumptions

You trust: the receipt you were given, the published public key (ideally pinned),
and the crypto libraries (`PyNaCl`/libsodium, `pycryptodome`; `tweetnacl`,
`js-sha3`). You do **not** trust TWZRD's API, database, or this repository's other
code. Swap the libraries for your own if you prefer - the byte layouts above (V5
prefix, V6 reputation block, V7 freshness wrap) are the whole leaf spec. V7 adds
two non-layout checks before the leaf is recomputed: the envelope must carry
`kind: "twzrd_reputation_receipt_v7"`, `version: "v7"` and `preimage.version: "v7"`,
and `recheck_after_unix` must equal `timestamp_unix + staleness_days * 86400`.
