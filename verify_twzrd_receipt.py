#!/usr/bin/env python3
"""
Standalone offline verifier for TWZRD receipts. Two families, auto-detected:

  A. AO-Receipt V5/V6 (trust-API): keccak256 leaf over a packed preimage,
     Ed25519-signed over the leaf bytes by the receipt key (9V6Pn19...).
  B. cNFT Receipt (genesis anchor): the compressed-NFT receipts, Ed25519 signed
     DIRECTLY over a compact-JSON payload (no keccak leaf) by the airship genesis
     authority (2ELSDx...), signature hex-encoded. Shape: { "anchor": { ... } }.
     `wallet` is part of the signed payload but lives in the <wallet>.json URL, so
     pass --wallet or name the file <wallet>.json.

Verifies, with NO trust in TWZRD's servers or codebase, that a receipt was
authored by TWZRD's published signing key and was not tampered with.

For trust-API receipts it checks two things:
  1. TAMPER-EVIDENCE  - recompute the keccak256 leaf from the receipt's preimage
                        and confirm it matches receipt.leaf.
  2. AUTHENTICITY     - verify the Ed25519 signature over the leaf bytes against
                        TWZRD's PUBLISHED public key (you supply it / fetch it
                        from the public endpoint; never from this script's word).
For cNFT receipts there is no leaf: tamper-evidence IS the signature - any change
to a signed field (incl. wallet) invalidates the Ed25519 sig over the compact JSON.

Trust model: you trust only (a) the receipt, (b) TWZRD's published public key,
and (c) two widely-audited crypto libraries (PyNaCl = libsodium for Ed25519,
pycryptodome for original Keccak-256). You do NOT trust TWZRD's server or code.

Dependencies (one install, both audited - or swap for your own):
    pip install pynacl pycryptodome

Usage:
    # verify a receipt file, fetching the published key from the live endpoint:
    python verify_twzrd_receipt.py receipt.json

    # verify against a pinned key you obtained out-of-band (most paranoid):
    python verify_twzrd_receipt.py receipt.json --pubkey 9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf

    # read receipt from stdin:
    curl ... | python verify_twzrd_receipt.py -

    # sanity-check the verifier itself (tamper must fail):
    python verify_twzrd_receipt.py receipt.json --self-test

Exit code 0 = VALID, 1 = INVALID / error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request

DEFAULT_BASE_URL = "https://intel.twzrd.xyz"
DOMAIN = b"TWZRD:AO_REPUTATION_RECEIPT_V5"
ATTENTION_DOMAIN = b"TWZRD:AO_ATTENTION_RECEIPT_V5"
# V6 binds the reputation_* provenance fields into the leaf (V5 left them unsigned).
REPUTATION_V6_DOMAIN = b"TWZRD:AO_REPUTATION_RECEIPT_V6"
ATTENTION_V6_DOMAIN = b"TWZRD:AO_ATTENTION_RECEIPT_V6"

# Known-good keccak256("") vector (original Keccak, the Ethereum variant - NOT SHA3).
_KECCAK_EMPTY = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    num = 0
    for c in s:
        num = num * 58 + _B58.index(c)
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def keccak256(data: bytes) -> bytes:
    from Crypto.Hash import keccak  # pycryptodome: original Keccak-f, matches the issuer
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def ed25519_verify(pubkey32: bytes, signature64: bytes, message: bytes) -> bool:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
    try:
        VerifyKey(pubkey32).verify(message, signature64)
        return True
    except BadSignatureError:
        return False


def _payer32(payer: str) -> bytes:
    """Real base58 pubkey -> 32 bytes; synthetic marker -> sha256(marker)."""
    try:
        raw = b58decode(payer)
        if len(raw) == 32:
            return raw
    except Exception:
        pass
    return hashlib.sha256(payer.encode("utf-8")).digest()


def _anchor32(settlement_tx: str | None) -> bytes:
    if not settlement_tx:
        return b"\x00" * 32
    raw = settlement_tx.encode("utf-8")
    return raw[-32:] if len(raw) >= 32 else (b"\x00" * (32 - len(raw))) + raw


def _encode_reputation_block_v6(pre: dict) -> bytes:
    """V6 reputation block: each field is a 1-byte presence flag (0x00 None /
    0x01 present) followed by the fixed-width value only when present. Order and
    encoding are fixed (see the issuer's RECEIPT_V6_LEAF_SPEC.md): reputation_score
    is i64 LE (null-vs-0 safe), confidence is u16 LE, version/data_quality are
    u16-length-prefixed UTF-8, feature_window is u64 LE. "" is present (distinct
    from None). This is what V6 binds into the leaf so reputation_* can't be forged."""

    def opt_int(value, width: int, signed: bool) -> bytes:
        if value is None:
            return b"\x00"
        return b"\x01" + int(value).to_bytes(width, "little", signed=signed)

    def opt_str(value) -> bytes:
        if value is None:
            return b"\x00"
        raw = str(value).encode("utf-8")
        return b"\x01" + len(raw).to_bytes(2, "little") + raw

    return (
        opt_int(pre.get("reputation_score"), 8, True)
        + opt_int(pre.get("reputation_confidence_bps"), 2, False)
        + opt_str(pre.get("reputation_score_version"))
        + opt_int(pre.get("reputation_feature_window_start_unix"), 8, False)
        + opt_str(pre.get("reputation_data_quality"))
    )


def recompute_leaf(pre: dict) -> bytes:
    # Use the exact domain string the receipt carries. V6 binds the reputation_*
    # provenance fields into the leaf (V5 left them unsigned/forgeable); a V6
    # receipt verified with V5 rules would fail on a legitimate receipt, so the
    # block is appended whenever the domain is _V6.
    domain_str = (pre.get("domain") or "").upper()
    is_v6 = "_V6" in domain_str
    is_attention = "ATTENTION" in domain_str
    if is_attention:
        domain = (ATTENTION_V6_DOMAIN if is_v6 else ATTENTION_DOMAIN)
        score = int(pre.get("attention_score") or 0)
    else:
        domain = (REPUTATION_V6_DOMAIN if is_v6 else DOMAIN)
        score = int(pre.get("score") or 0)
    agent = (pre["agent_id"]).encode("utf-8")
    msg = (
        domain
        + len(agent).to_bytes(2, "little")
        + agent
        + score.to_bytes(2, "little")
        + int(pre["confidence_bps"]).to_bytes(2, "little")
        + int(pre["timestamp_unix"]).to_bytes(8, "little")
        + _payer32(pre["payer"])
        + _anchor32(pre.get("settlement_tx") or pre.get("settlement_anchor"))
    )
    if is_v6:
        msg += _encode_reputation_block_v6(pre)
    return keccak256(msg)


def fetch_published_pubkey(base_url: str) -> str:
    base = base_url.rstrip("/")
    headers = {"User-Agent": "twzrd-receipt-verifier/1.0"}
    for path in (
        "/.well-known/twzrd-receipt-pubkey",
        "/v1/intel/pubkey",
        "/.well-known/x402",
    ):
        url = base + path
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            doc = json.load(r)
        if path.endswith("/x402"):
            return doc["receipt"]["signature"]["public_key"]
        return doc["public_key"]


def verify(receipt: dict, trusted_pubkey_b58: str, max_age_seconds: int | None = None) -> dict:
    out = {"leaf_valid": False, "signature_valid": False, "errors": []}
    pre = receipt.get("preimage") or {}
    leaf_hex = (receipt.get("leaf") or "").lower().removeprefix("0x")

    try:
        recomputed = recompute_leaf(pre)
    except Exception as exc:
        out["errors"].append(f"could not recompute leaf: {exc}")
        return out
    out["recomputed_leaf"] = "0x" + recomputed.hex()
    out["leaf_valid"] = (recomputed.hex() == leaf_hex)
    if not out["leaf_valid"]:
        out["errors"].append("leaf mismatch: preimage does not hash to receipt.leaf")

    sig = receipt.get("signature")
    if not sig:
        out["errors"].append("missing signature (unsigned receipts are rejected)")
        return out

    embedded = receipt.get("signing_pubkey")
    if embedded and embedded != trusted_pubkey_b58:
        out["errors"].append(
            f"signing_pubkey {embedded} != trusted published key {trusted_pubkey_b58}"
        )
        return out

    try:
        out["signature_valid"] = ed25519_verify(
            b58decode(trusted_pubkey_b58), b58decode(sig), recomputed
        )
    except Exception as exc:
        out["errors"].append(f"signature check error: {exc}")
        return out
    if not out["signature_valid"]:
        out["errors"].append("signature not valid for the trusted published key")

    # Optional freshness window for replay resistance (mirrors the JS/TS verifier
    # and twzrd_agent_intel.receipt.verify_receipt max_age_seconds). The crypto
    # above is time-independent; this is an extra relying-party policy gate.
    if max_age_seconds is not None and max_age_seconds > 0:
        import time

        age = abs(int(time.time()) - int(pre.get("timestamp_unix", 0) or 0))
        if age > max_age_seconds:
            out["errors"].append(
                f"receipt too old (age {age}s > max_age_seconds {max_age_seconds})"
            )

    out["valid"] = out["leaf_valid"] and out["signature_valid"] and not out["errors"]
    out["trusted_pubkey"] = trusted_pubkey_b58
    return out


# ── cNFT (Bubblegum anchor) receipts ──────────────────────────────────────
# The genesis compressed-NFT receipts are NOT keccak-leaf receipts. Each is an
# Ed25519 signature made DIRECTLY over the UTF-8 bytes of a compact JSON object,
# in a fixed key order (mirrors airship.ts payload() and the Node verifier). The
# airship genesis authority key is baked in as out-of-band pinning; override with
# --pubkey. It matches verify_pubkey in every anchor and the verified creator on
# every cNFT in tree 8QFdTqBkSeyuvp47dXdpwfWzXTuYSbAC64oT4soPGnXS.
DEFAULT_CNFT_PUBKEY = "2ELSDxLkb7dYrN6EUG69tNtULAq4Fo7WPvXyrZPmuFif"
# Where --fetch-key looks for the published cNFT key descriptor.
DEFAULT_CNFT_BASE_URL = "https://api.twzrd.xyz"
CNFT_SIGNED_FIELDS = ["wallet", "tier_at_mint", "score_at_mint", "verified_tx", "behavior_proof", "minted_at"]


def fetch_cnft_pubkey(base_url: str) -> str:
    """Fetch the published cNFT signing-key descriptor (for --fetch-key) and return the
    base58 pubkey. Trades package-trust for domain/TLS-trust; the built-in key is the
    default precisely because it needs no network."""
    base = base_url.rstrip("/")
    headers = {"User-Agent": "twzrd-receipt-verifier/cnft"}
    last = None
    for path in ("/v1/receipts/pubkey", "/.well-known/twzrd-receipt-pubkey"):
        try:
            req = urllib.request.Request(base + path, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as r:
                pk = json.load(r).get("public_key")
            if pk:
                return pk
        except Exception as exc:  # try next path
            last = exc
    raise RuntimeError(f"no cNFT pubkey endpoint responded ({last})")


def is_cnft_receipt(receipt: dict) -> bool:
    """A cNFT receipt is the metadata JSON served at /r/<wallet>.json: it carries an
    `anchor` block (at-mint snapshot + signature) instead of a keccak `leaf`."""
    if not isinstance(receipt, dict):
        return False
    a = receipt.get("anchor")
    return bool(isinstance(a, dict) and a.get("signature")
                and (a.get("tier_at_mint") is not None or a.get("score_at_mint") is not None))


def cnft_signed_payload(anchor: dict, wallet: str) -> bytes:
    """Reconstruct the exact bytes the issuer signed (airship.ts). Compact separators
    + ensure_ascii=False reproduce JS JSON.stringify byte-for-byte. `wallet` is the
    first signed field but is NOT in the anchor block (it is the leaf owner / the
    <wallet>.json filename), so the caller supplies it. Key order is fixed."""
    obj = {
        "wallet": wallet,
        "tier_at_mint": anchor.get("tier_at_mint"),
        "score_at_mint": anchor.get("score_at_mint"),
        "verified_tx": anchor.get("verified_tx"),
        "behavior_proof": anchor.get("behavior_proof"),
        "minted_at": anchor.get("minted_at"),
    }
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def resolve_wallet(explicit_wallet=None, receipt=None, receipt_path=None):
    """Resolve the wallet from (in priority): --wallet, the receipt body (future
    formats), or a <wallet>.json filename whose stem base58-decodes to 32 bytes."""
    if explicit_wallet:
        return explicit_wallet, "--wallet"
    if isinstance(receipt, dict) and isinstance(receipt.get("wallet"), str):
        return receipt["wallet"], "receipt.wallet"
    if (isinstance(receipt, dict) and isinstance(receipt.get("anchor"), dict)
            and isinstance(receipt["anchor"].get("wallet"), str)):
        return receipt["anchor"]["wallet"], "anchor.wallet"
    if receipt_path and receipt_path != "-":
        import os
        stem = os.path.basename(receipt_path)
        if stem.lower().endswith(".json"):
            stem = stem[:-5]
        try:
            if len(b58decode(stem)) == 32:
                return stem, "filename"
        except Exception:
            pass
    return None, "none"


def verify_cnft(receipt: dict, trusted_pubkey_b58: str, wallet, max_age_seconds: int | None = None) -> dict:
    """Authenticity for a cNFT receipt: Ed25519-verify the hex signature over the
    reconstructed compact-JSON payload. No keccak leaf - tamper-evidence is the
    signature itself; any change to a signed field (incl. wallet) invalidates it."""
    out = {"mode": "cnft", "signature_valid": False, "errors": []}
    a = (receipt.get("anchor") or {}) if isinstance(receipt, dict) else {}
    out["wallet"] = wallet
    if not wallet:
        out["errors"].append(
            "cNFT receipt: wallet unknown - it is part of the signed payload but not in the "
            "anchor block. Pass --wallet <addr> or name the file <wallet>.json."
        )
        return out
    embedded = a.get("verify_pubkey")
    if embedded and embedded != trusted_pubkey_b58:
        out["errors"].append(f"anchor.verify_pubkey {embedded} != trusted key {trusted_pubkey_b58}")
        return out
    sig_hex = str(a.get("signature") or "").lower()
    if sig_hex.startswith("0x"):
        sig_hex = sig_hex[2:]
    if not sig_hex:
        out["errors"].append("missing anchor.signature")
        return out
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError as exc:
        out["errors"].append(f"anchor.signature not hex: {exc}")
        return out
    if len(sig) != 64:
        out["errors"].append(f"anchor.signature must be 64 bytes (got {len(sig)})")
        return out
    msg = cnft_signed_payload(a, wallet)
    out["signed_payload"] = msg.decode("utf-8")
    try:
        out["signature_valid"] = ed25519_verify(b58decode(trusted_pubkey_b58), sig, msg)
    except Exception as exc:
        out["errors"].append(f"signature check error: {exc}")
        return out
    if not out["signature_valid"]:
        out["errors"].append("signature not valid for the trusted key (payload tampered, or wrong --wallet / --pubkey)")

    # Opt-in freshness gate (anchor.minted_at). cNFT receipts are long-lived by
    # design; kept for parity with the trust-API path.
    if max_age_seconds is not None and max_age_seconds > 0:
        import time
        ts = int(a.get("minted_at", 0) or 0)
        if ts <= 0:
            out["errors"].append(f"--max-age {max_age_seconds}s set but anchor has no valid minted_at")
        else:
            age = abs(int(time.time()) - ts)
            if age > max_age_seconds:
                out["errors"].append(f"receipt too old (age {age}s > max_age_seconds {max_age_seconds})")

    out["valid"] = out["signature_valid"] and not out["errors"]
    out["trusted_pubkey"] = trusted_pubkey_b58
    return out


def _keccak_selftest() -> None:
    got = keccak256(b"").hex()
    if got != _KECCAK_EMPTY:
        raise SystemExit(
            f"FATAL: keccak256 backend is wrong (got {got}, want {_KECCAK_EMPTY}). "
            "Refusing to verify with a broken hash."
        )


def unwrap_receipt(obj):
    """API responses nest the receipt under `twzrd_receipt` (GET /v1/intel/trust,
    GET /v1/receipts/example); accept them directly so piped curl output verifies."""
    if (
        isinstance(obj, dict)
        and "preimage" not in obj
        and "anchor" not in obj
        and isinstance(obj.get("twzrd_receipt"), dict)
    ):
        return obj["twzrd_receipt"]
    return obj


def main() -> int:
    ap = argparse.ArgumentParser(description="Standalone TWZRD v5/v6 receipt verifier")
    ap.add_argument("receipt", help="path to receipt JSON, or '-' for stdin")
    ap.add_argument("--pubkey", help="trusted published pubkey (base58); if omitted, fetched (trust-API) or built-in (cNFT)")
    ap.add_argument("--wallet", help="(cNFT only) leaf-owner wallet; part of the signed payload but not in the anchor block. Inferred from a <wallet>.json filename if omitted.")
    ap.add_argument("--fetch-key", action="store_true",
                    help=f"(cNFT only) fetch the signing key from the published descriptor (--base-url or {DEFAULT_CNFT_BASE_URL}) instead of the built-in copy")
    ap.add_argument("--base-url", default=None,
                    help=f"key fetch source; trust-API default {DEFAULT_BASE_URL}, cNFT (--fetch-key) default {DEFAULT_CNFT_BASE_URL}")
    ap.add_argument("--self-test", action="store_true", help="also confirm a tampered receipt FAILS")
    ap.add_argument(
        "--max-age",
        type=int,
        default=None,
        metavar="SECONDS",
        help="reject receipts older than N seconds (replay-resistance policy; omitted = no age check)",
    )
    args = ap.parse_args()

    raw = sys.stdin.read() if args.receipt == "-" else open(args.receipt).read()
    receipt = unwrap_receipt(json.loads(raw))

    # ── cNFT (Bubblegum anchor) receipt: Ed25519 over compact JSON, no keccak leaf ──
    if is_cnft_receipt(receipt):
        if args.pubkey:
            trusted = args.pubkey
            key_src = "--pubkey (out-of-band)"
        elif args.fetch_key:
            fetch_base = args.base_url or DEFAULT_CNFT_BASE_URL
            trusted = fetch_cnft_pubkey(fetch_base)
            key_src = f"fetched from {fetch_base}"
        else:
            trusted = DEFAULT_CNFT_PUBKEY
            key_src = "built-in genesis authority"
        wallet, wallet_src = resolve_wallet(
            explicit_wallet=args.wallet, receipt=receipt, receipt_path=args.receipt
        )
        print("mode             : cNFT (Bubblegum anchor)")
        print(f"trusted pubkey   : {trusted}  [source: {key_src}]")
        print(f"wallet           : {wallet or '(unknown)'}  [source: {wallet_src}]")

        res = verify_cnft(receipt, trusted, wallet, max_age_seconds=args.max_age)
        print(f"signature_valid  : {res['signature_valid']}")
        for e in res.get("errors", []):
            print(f"  - {e}")
        ok = bool(res.get("valid"))
        print(f"RESULT           : {'VALID (TWZRD-authored, untampered)' if ok else 'INVALID'}")

        if args.self_test:
            tampered = unwrap_receipt(json.loads(raw))
            tampered.setdefault("anchor", {})
            cur = tampered["anchor"].get("score_at_mint") or 0
            tampered["anchor"]["score_at_mint"] = cur + 1
            t = verify_cnft(tampered, trusted, wallet)
            passed = not t.get("valid")
            print(f"self-test (tampered score must FAIL): {'PASS' if passed else 'BROKEN'}")
            ok = ok and passed

        return 0 if ok else 1

    # ── trust-API receipt (V5/V6): keccak256 leaf, signed over the leaf bytes ──
    _keccak_selftest()

    if args.pubkey:
        trusted = args.pubkey
        src = "--pubkey (out-of-band)"
    else:
        trust_base = args.base_url or DEFAULT_BASE_URL
        trusted = fetch_published_pubkey(trust_base)
        src = f"{trust_base}/.well-known/x402"
    print("mode             : AO-Receipt (trust-API)")
    print(f"trusted pubkey   : {trusted}  [source: {src}]")

    res = verify(receipt, trusted, max_age_seconds=args.max_age)
    print(f"leaf_valid       : {res['leaf_valid']}")
    print(f"signature_valid  : {res['signature_valid']}")
    if res.get("errors"):
        for e in res["errors"]:
            print(f"  - {e}")
    ok = bool(res.get("valid"))
    print(f"RESULT           : {'VALID (TWZRD-authored, untampered)' if ok else 'INVALID'}")

    if args.self_test:
        tampered = unwrap_receipt(json.loads(raw))
        tampered.setdefault("preimage", {})
        cur = tampered["preimage"].get("score") or 0
        tampered["preimage"]["score"] = cur + 1
        t = verify(tampered, trusted)
        passed = not t.get("valid")
        print(f"self-test (tampered score must FAIL): {'PASS' if passed else 'BROKEN'}")
        ok = ok and passed

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
