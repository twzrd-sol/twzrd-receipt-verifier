"""Tests for the standalone TWZRD AO-Receipt V5 verifier (verify_twzrd_receipt.py).

This package is the independent, zero-trust verifier external parties run to
confirm a TWZRD reputation receipt is genuinely signed -- so it MUST fail closed
on forged / tampered / unsigned receipts and accept a genuinely-signed one.

The tests are fully self-contained: a receipt is signed in-test using ONLY the
verifier's own primitives (recompute_leaf) plus the package's declared crypto
deps (PyNaCl), with no dependency on twzrd_agent_intel -- preserving the
package's "no trust in TWZRD servers or code" property.
"""

import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

# Import the verifier module (one dir up from tests/).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify_twzrd_receipt as V  # noqa: E402

# Deterministic test key (00 01 ... 1f). NOT a production key.
_SK = SigningKey(bytes(range(32)))
_VK_RAW = bytes(_SK.verify_key)

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return _B58_ALPHABET[0] * pad + out


TRUSTED_PUBKEY = _b58encode(_VK_RAW)

BASE_PREIMAGE = {
    "domain": "TWZRD:GLOBAL_V5",
    "agent_id": "agent_test01",
    "score": 77,
    "confidence_bps": 8000,
    "timestamp_unix": 1_750_000_000,
    "payer": "11111111111111111111111111111112",
    "settlement_tx": None,
}


def _signed_receipt(preimage: dict) -> dict:
    """Build a receipt the verifier will accept: leaf = recompute_leaf(preimage),
    signature = Ed25519(leaf) by the trusted key."""
    leaf = V.recompute_leaf(preimage)
    sig = _SK.sign(leaf).signature
    return {
        "preimage": dict(preimage),
        "leaf": "0x" + leaf.hex(),
        "signature": _b58encode(sig),
        "signing_pubkey": TRUSTED_PUBKEY,
    }


def test_genuine_receipt_verifies():
    res = V.verify(_signed_receipt(BASE_PREIMAGE), TRUSTED_PUBKEY)
    assert res["leaf_valid"] is True, res.get("errors")
    assert res["signature_valid"] is True, res.get("errors")
    assert res["errors"] == []


def test_unsigned_receipt_is_rejected():
    rec = _signed_receipt(BASE_PREIMAGE)
    rec.pop("signature")
    res = V.verify(rec, TRUSTED_PUBKEY)
    assert res["signature_valid"] is False
    assert any("unsigned" in e or "missing signature" in e for e in res["errors"])


def test_tampered_score_breaks_leaf():
    """Change a signed field in the preimage -> leaf no longer matches and the
    signature (over the original leaf) is invalid for the recomputed leaf."""
    rec = _signed_receipt(BASE_PREIMAGE)
    rec["preimage"]["score"] = 999  # was 77
    res = V.verify(rec, TRUSTED_PUBKEY)
    assert res["leaf_valid"] is False
    assert res["signature_valid"] is False


def test_tampered_payer_breaks_leaf():
    rec = _signed_receipt(BASE_PREIMAGE)
    rec["preimage"]["payer"] = "So11111111111111111111111111111111111111112"
    res = V.verify(rec, TRUSTED_PUBKEY)
    assert res["leaf_valid"] is False
    assert res["signature_valid"] is False


def test_forged_signature_is_rejected():
    """A signature from a different key must not verify against the trusted key."""
    rec = _signed_receipt(BASE_PREIMAGE)
    attacker = SigningKey(bytes([1]) + bytes(range(31)))
    leaf = V.recompute_leaf(rec["preimage"])
    rec["signature"] = _b58encode(attacker.sign(leaf).signature)
    res = V.verify(rec, TRUSTED_PUBKEY)
    assert res["leaf_valid"] is True  # leaf itself untouched
    assert res["signature_valid"] is False


def test_wrong_trusted_key_is_rejected():
    """A genuine receipt checked against a DIFFERENT trusted key fails, and the
    embedded signing_pubkey mismatch is caught before the crypto check."""
    rec = _signed_receipt(BASE_PREIMAGE)
    other_key = _b58encode(bytes(SigningKey(bytes([2]) + bytes(range(31))).verify_key))
    res = V.verify(rec, other_key)
    assert res["signature_valid"] is False
    assert any("!= trusted published key" in e for e in res["errors"])


def test_expiry_window_rejects_stale_receipt():
    """With a max_age_seconds window, a receipt older than the window is flagged."""
    rec = _signed_receipt(BASE_PREIMAGE)  # timestamp_unix = 1_750_000_000
    # now is far in the future relative to the receipt timestamp.
    res = V.verify(rec, TRUSTED_PUBKEY, max_age_seconds=60)
    # Signature is still cryptographically valid...
    assert res["signature_valid"] is True
    # ...but the freshness check should record an expiry error (replay resistance).
    assert any("expired" in e.lower() or "stale" in e.lower() or "age" in e.lower()
               for e in res["errors"]), res["errors"]


# ── V6: reputation_* fields bound into the leaf ─────────────────────
# Canonical vector shared with the issuer (RECEIPT_V6_LEAF_SPEC.md), the Rust
# crate, and the TS SDK. This verifier MUST reproduce the same leaf or it cannot
# verify a real V6 receipt from intel.twzrd.xyz.
CANON_V6_PREIMAGE = {
    "domain": "TWZRD:AO_REPUTATION_RECEIPT_V6",
    "agent_id": "11111111111111111111111111111111",
    "score": 72,
    "confidence_bps": 8000,
    "timestamp_unix": 1748736000,
    "payer": "11111111111111111111111111111111",
    "settlement_tx": "EXAMPLE-sample-receipt-no-real-settlement-tx-0001",
    "reputation_score": 4242,
    "reputation_confidence_bps": 7500,
    "reputation_score_version": "intel_renorm_v1",
    "reputation_feature_window_start_unix": 1748000000,
    "reputation_data_quality": "high",
}
CANON_V6_LEAF = "4c82649d2be393b1fca2da7c5d4c7afebb189ad3f0b93b620ce2e552fe5ce558"


def test_v6_canonical_leaf():
    assert V.recompute_leaf(CANON_V6_PREIMAGE).hex() == CANON_V6_LEAF


def test_v6_block_hex():
    block = V._encode_reputation_block_v6(CANON_V6_PREIMAGE)
    assert block.hex() == "019210000000000000014c1d010f00696e74656c5f72656e6f726d5f763101005d30680000000001040068696768"


def test_v6_genuine_receipt_verifies():
    res = V.verify(_signed_receipt(CANON_V6_PREIMAGE), TRUSTED_PUBKEY)
    assert res["leaf_valid"] is True, res.get("errors")
    assert res["signature_valid"] is True, res.get("errors")


def test_v6_forged_reputation_field_breaks_leaf():
    """The exact bug V6 closes: in V5 reputation_* sat OUTSIDE the leaf, so a
    receipt holder could forge reputation_score / reputation_data_quality under a
    real signature. Under V6 they are bound, so mutating any must break the leaf."""
    rec = _signed_receipt(CANON_V6_PREIMAGE)
    rec["preimage"]["reputation_score"] = 9999  # was 4242
    rec["preimage"]["reputation_data_quality"] = "PWNED"
    res = V.verify(rec, TRUSTED_PUBKEY)
    assert res["leaf_valid"] is False
    assert res["signature_valid"] is False


def test_v6_empty_string_distinct_from_null():
    null_block = V._encode_reputation_block_v6({"reputation_data_quality": None})
    empty_block = V._encode_reputation_block_v6({"reputation_data_quality": ""})
    assert null_block != empty_block
