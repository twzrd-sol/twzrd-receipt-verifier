#!/usr/bin/env python3
"""
Standalone offline verifier for TWZRD AO-Receipt V5.

Verifies, with NO trust in TWZRD's servers or codebase, that a receipt was
authored by TWZRD's published signing key and was not tampered with.

It checks two things:
  1. TAMPER-EVIDENCE  - recompute the keccak256 leaf from the receipt's preimage
                        and confirm it matches receipt.leaf.
  2. AUTHENTICITY     - verify the Ed25519 signature over the leaf bytes against
                        TWZRD's PUBLISHED public key (you supply it / fetch it
                        from the public endpoint; never from this script's word).

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


def _keccak_selftest() -> None:
    got = keccak256(b"").hex()
    if got != _KECCAK_EMPTY:
        raise SystemExit(
            f"FATAL: keccak256 backend is wrong (got {got}, want {_KECCAK_EMPTY}). "
            "Refusing to verify with a broken hash."
        )


def main() -> int:
    ap = argparse.ArgumentParser(description="Standalone TWZRD V5 receipt verifier")
    ap.add_argument("receipt", help="path to receipt JSON, or '-' for stdin")
    ap.add_argument("--pubkey", help="trusted published pubkey (base58); if omitted, fetched from --base-url")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL)
    ap.add_argument("--self-test", action="store_true", help="also confirm a tampered receipt FAILS")
    ap.add_argument(
        "--max-age",
        type=int,
        default=None,
        metavar="SECONDS",
        help="reject receipts older than N seconds (replay-resistance policy; omitted = no age check)",
    )
    args = ap.parse_args()

    _keccak_selftest()

    raw = sys.stdin.read() if args.receipt == "-" else open(args.receipt).read()
    receipt = json.loads(raw)

    if args.pubkey:
        trusted = args.pubkey
        src = "--pubkey (out-of-band)"
    else:
        trusted = fetch_published_pubkey(args.base_url)
        src = f"{args.base_url}/.well-known/x402"
    print(f"trusted pubkey: {trusted}  [source: {src}]")

    res = verify(receipt, trusted, max_age_seconds=args.max_age)
    print(f"leaf_valid       : {res['leaf_valid']}")
    print(f"signature_valid  : {res['signature_valid']}")
    if res.get("errors"):
        for e in res["errors"]:
            print(f"  - {e}")
    ok = bool(res.get("valid"))
    print(f"RESULT           : {'VALID (TWZRD-authored, untampered)' if ok else 'INVALID'}")

    if args.self_test:
        tampered = json.loads(raw)
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
