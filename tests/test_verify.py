"""Tests for the standalone TWZRD AO-Receipt V5 verifier (verify_twzrd_receipt.py).

This package is the independent, zero-trust verifier external parties run to
confirm a TWZRD reputation receipt is genuinely signed -- so it MUST fail closed
on forged / tampered / unsigned receipts and accept a genuinely-signed one.

The tests are fully self-contained: a receipt is signed in-test using ONLY the
verifier's own primitives (recompute_leaf) plus the package's declared crypto
deps (PyNaCl), with no dependency on twzrd_agent_intel -- preserving the
package's "no trust in TWZRD servers or code" property.
"""

import json
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
    "domain": "TWZRD:AO_REPUTATION_RECEIPT_V5",
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
        "key_id": V.CURRENT_RECEIPT_SIGNING_KEY_ID,
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
    assert any("is not trusted" in e for e in res["errors"])


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
    # Canonical vector has no freshness triple, so empty is honest.
    assert res["unauthenticated_fields"] == []


def test_v6_freshness_triple_is_unauthenticated():
    pre = dict(
        CANON_V6_PREIMAGE,
        recheck_after_unix=CANON_V6_PREIMAGE["timestamp_unix"] + 3 * 86400,
        staleness_days=3,
        score_decay_model="step:<=7d=1.0,<=30d=0.8,<=90d=0.5,>90d=0.25",
    )
    res = V.verify(_signed_receipt(pre), TRUSTED_PUBKEY)
    assert res["leaf_valid"] is True, res.get("errors")
    assert set(res["unauthenticated_fields"]) == {
        "recheck_after_unix",
        "staleness_days",
        "score_decay_model",
    }


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


# Locked lists from verifier source (RECEIPT_V6_LEAF_SPEC.md / #1975/#1980).
# Freshness is JSON-only. V6 BOUND = V5 prefix + reputation block.
_LOCKED_FRESHNESS = (
    "recheck_after_unix",
    "staleness_days",
    "score_decay_model",
)
_LOCKED_V6_REPUTATION_BOUND = (
    "reputation_score",
    "reputation_confidence_bps",
    "reputation_score_version",
    "reputation_feature_window_start_unix",
    "reputation_data_quality",
)


def _v6_pre_with_freshness() -> dict:
    return dict(
        CANON_V6_PREIMAGE,
        recheck_after_unix=CANON_V6_PREIMAGE["timestamp_unix"] + 3 * 86400,
        staleness_days=3,
        score_decay_model="step:<=7d=1.0,<=30d=0.8,<=90d=0.5,>90d=0.25",
    )


def test_v6_card_sample_lists_freshness_only_as_freshness():
    pre = _v6_pre_with_freshness()
    rec = _signed_receipt(pre)
    res = V.verify(rec, TRUSTED_PUBKEY)
    card = V.format_bound_freshness_card(rec, res)
    assert res["leaf_valid"] is True
    assert res["signature_valid"] is True
    assert V.card_verdict(rec, res) == "valid-signature"
    assert "VERDICT   valid-signature" in card
    for name in _LOCKED_FRESHNESS:
        assert f"FRESHNESS {name}" in card
        assert f"BOUND     {name}" not in card
    for name in _LOCKED_V6_REPUTATION_BOUND:
        assert f"BOUND     {name}" in card
        assert f"FRESHNESS {name}" not in card


def test_v6_card_tamper_bound_field_invalid():
    rec = _signed_receipt(_v6_pre_with_freshness())
    rec["preimage"]["reputation_score"] = 9999
    res = V.verify(rec, TRUSTED_PUBKEY)
    card = V.format_bound_freshness_card(rec, res)
    assert res["leaf_valid"] is False
    assert V.card_verdict(rec, res) == "invalid"
    assert "VERDICT   invalid" in card


def test_v6_card_tamper_freshness_still_valid_signature():
    rec = _signed_receipt(_v6_pre_with_freshness())
    rec["preimage"]["staleness_days"] = 99
    rec["preimage"]["recheck_after_unix"] = 1
    rec["preimage"]["score_decay_model"] = "forged"
    res = V.verify(rec, TRUSTED_PUBKEY)
    card = V.format_bound_freshness_card(rec, res)
    assert res["leaf_valid"] is True
    assert res["signature_valid"] is True
    assert V.card_verdict(rec, res) == "valid-signature"
    assert "VERDICT   valid-signature" in card
    assert "FRESHNESS staleness_days" in card
    assert "FRESHNESS recheck_after_unix" in card
    assert "FRESHNESS score_decay_model" in card


def test_v6_locked_lists_freshness_never_in_signed_set():
    # Fail if a freshness name is merged into the signed constants.
    assert V.FRESHNESS_UNAUTHENTICATED_FIELDS == _LOCKED_FRESHNESS
    assert V.REPUTATION_PROVENANCE_FIELDS == _LOCKED_V6_REPUTATION_BOUND
    overlap = set(V.FRESHNESS_UNAUTHENTICATED_FIELDS) & set(V.REPUTATION_PROVENANCE_FIELDS)
    assert overlap == set()
    overlap_prefix = set(V.FRESHNESS_UNAUTHENTICATED_FIELDS) & set(V.V5_PREFIX_BOUND_FIELDS)
    assert overlap_prefix == set()
    pre = _v6_pre_with_freshness()
    bound = V.bound_field_names(pre, is_v6=True)
    fresh = V.freshness_field_names(pre)
    assert set(fresh) == set(_LOCKED_FRESHNESS)
    assert set(_LOCKED_V6_REPUTATION_BOUND).issubset(bound)
    assert set(fresh).isdisjoint(bound)


def test_unsigned_card_verdict():
    rec = _signed_receipt(_v6_pre_with_freshness())
    rec.pop("signature")
    res = V.verify(rec, TRUSTED_PUBKEY)
    assert V.card_verdict(rec, res) == "unsigned"


def test_v6_card_lists_only_settlement_key_in_leaf():
    """recompute_leaf uses settlement_tx or settlement_anchor, not both."""
    pre = _v6_pre_with_freshness()
    pre["settlement_anchor"] = "deadbeef-not-in-leaf-when-tx-present"
    rec = _signed_receipt(pre)
    res = V.verify(rec, TRUSTED_PUBKEY)
    card = V.format_bound_freshness_card(rec, res)
    assert "BOUND     settlement_tx" in card
    assert "BOUND     settlement_anchor" not in card
    rec["preimage"]["settlement_anchor"] = "TAMPERED"
    res2 = V.verify(rec, TRUSTED_PUBKEY)
    assert V.card_verdict(rec, res2) == "valid-signature"


def test_checked_in_example_unused_anchor_not_bound():
    """Skeptic repro: testdata has both keys; only settlement_tx entered the leaf."""
    path = Path(__file__).resolve().parents[1] / "testdata" / "v6_example.json"
    rec = V.unwrap_receipt(json.loads(path.read_text(encoding="utf-8")))
    pub = rec["signing_pubkey"]
    res = V.verify(rec, pub)
    card = V.format_bound_freshness_card(rec, res)
    assert V.card_verdict(rec, res) == "valid-signature"
    assert "BOUND     settlement_tx" in card
    assert "BOUND     settlement_anchor" not in card
    rec["preimage"]["settlement_anchor"] = "TAMPERED-UNUSED"
    res2 = V.verify(rec, pub)
    card2 = V.format_bound_freshness_card(rec, res2)
    assert V.card_verdict(rec, res2) == "valid-signature"
    assert "BOUND     settlement_anchor" not in card2


def test_cli_receipt_flag_prints_card(tmp_path):
    """Drive the shipped CLI entry on a checked-in-style file via --receipt."""
    import subprocess

    pre = _v6_pre_with_freshness()
    rec = _signed_receipt(pre)
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(rec), encoding="utf-8")
    cli = Path(__file__).resolve().parents[1] / "verify_twzrd_receipt.py"
    proc = subprocess.run(
        [sys.executable, str(cli), "--receipt", str(path), "--pubkey", TRUSTED_PUBKEY],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    out = proc.stdout
    assert "BOUND     reputation_score" in out
    assert "FRESHNESS recheck_after_unix" in out
    assert "VERDICT   valid-signature" in out
    assert "BOUND     recheck_after_unix" not in out
    assert "trusted_due      : false" in out
    assert "trusted_allow    : false" in out
    assert "freshness_bound  : false" in out


# ── cNFT (Bubblegum anchor) receipts ────────────────────────────────────
# Different scheme from the keccak-leaf receipts above: Ed25519 over a compact-JSON
# payload (no leaf), hex signature, signed by the airship authority. `wallet` is the
# first signed field but lives in the <wallet>.json URL, not the anchor block.
import json as _json  # noqa: E402

CNFT_WALLET = "11111111111111111111111111111112"  # valid 32-byte base58 stand-in
CNFT_FIELDS = {
    "tier_at_mint": "Gold", "score_at_mint": 123,
    "verified_tx": "TESTtxSignatureNotReal", "behavior_proof": "deadbeef", "minted_at": 1750000000,
}


def _signed_cnft(wallet, fields, sk=_SK):
    """Mirror airship.ts payload(): compact JSON, exact key order, then Ed25519 sign."""
    payload = _json.dumps({
        "wallet": wallet,
        "tier_at_mint": fields["tier_at_mint"],
        "score_at_mint": fields["score_at_mint"],
        "verified_tx": fields["verified_tx"],
        "behavior_proof": fields["behavior_proof"],
        "minted_at": fields["minted_at"],
    }, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = sk.sign(payload).signature
    return {"anchor": {**fields, "signature": sig.hex(),
                       "verify_pubkey": _b58encode(bytes(sk.verify_key))}}


def test_cnft_detected():
    assert V.is_cnft_receipt(_signed_cnft(CNFT_WALLET, CNFT_FIELDS)) is True
    assert V.is_cnft_receipt(_signed_receipt(BASE_PREIMAGE)) is False


def test_cnft_genuine_verifies():
    res = V.verify_cnft(_signed_cnft(CNFT_WALLET, CNFT_FIELDS), TRUSTED_PUBKEY, CNFT_WALLET)
    assert res["signature_valid"] is True, res.get("errors")
    assert res["valid"] is True


def test_cnft_tampered_score_rejected():
    rec = _signed_cnft(CNFT_WALLET, CNFT_FIELDS)
    rec["anchor"]["score_at_mint"] = 999
    res = V.verify_cnft(rec, TRUSTED_PUBKEY, CNFT_WALLET)
    assert res["signature_valid"] is False
    assert res["valid"] is False


def test_cnft_wrong_wallet_rejected():
    """wallet is bound into the signature, so a different wallet must fail."""
    rec = _signed_cnft(CNFT_WALLET, CNFT_FIELDS)
    res = V.verify_cnft(rec, TRUSTED_PUBKEY, "So11111111111111111111111111111111111111112")
    assert res["signature_valid"] is False


def test_cnft_missing_wallet_errors():
    res = V.verify_cnft(_signed_cnft(CNFT_WALLET, CNFT_FIELDS), TRUSTED_PUBKEY, None)
    assert "valid" not in res
    assert any("wallet unknown" in e for e in res["errors"])


def test_cnft_wrong_key_rejected():
    rec = _signed_cnft(CNFT_WALLET, CNFT_FIELDS)
    other = _b58encode(bytes(SigningKey(bytes([7]) + bytes(range(31))).verify_key))
    res = V.verify_cnft(rec, other, CNFT_WALLET)
    assert res["signature_valid"] is False
    assert any("verify_pubkey" in e and "!= trusted key" in e for e in res["errors"])


def test_cnft_forged_signature_rejected():
    """Hardest case: anchor claims the trusted key, but the sig is the attacker's."""
    attacker = SigningKey(bytes([9]) + bytes(range(31)))
    rec = _signed_cnft(CNFT_WALLET, CNFT_FIELDS, sk=attacker)
    rec["anchor"]["verify_pubkey"] = TRUSTED_PUBKEY
    res = V.verify_cnft(rec, TRUSTED_PUBKEY, CNFT_WALLET)
    assert res["signature_valid"] is False
    assert res["valid"] is False


def test_resolve_wallet_from_filename():
    w, src = V.resolve_wallet(receipt_path=f"/tmp/{CNFT_WALLET}.json")
    assert w == CNFT_WALLET
    assert src == "filename"


def test_resolve_wallet_rejects_non_pubkey_filename():
    w, src = V.resolve_wallet(receipt_path="/tmp/not-a-wallet.json")
    assert w is None
    assert src == "none"


# REAL production fixture (identical to the Node suite) — locks the Python verifier
# to the actual genesis signer's output and guarantees JS<->Python agreement on cNFT.
# As served at https://twzrd.xyz/r/<wallet>.json, bound on-chain in tree 8QFdTqBk...
REAL_WALLET = "zoz7neLHXoaLwNBuckSqNqaMsacpqJsphtFuNNpQyt3"
REAL_ANCHOR = {
    "anchor": {
        "tier_at_mint": "Platinum",
        "score_at_mint": 255,
        "verified_tx": "4StuBXZr4LBWVGtTdWKdFFpM9NFWSzofmChT7QjrBYHSQZ81bEbW9h7EyyPh63N5EsMHAeXSRFCiKvSMiEg2QNUn",
        "behavior_proof": "2c5074ccfabd7360ff8bca0607483eadcb0e8b74e6bfe7b3de864b2614d64d46",
        "minted_at": 1782415336,
        "signature": "ec3bfe6f9e65e0ee69fea39ea35db1e7d5a30930cd6357576cf4b2221b626c7a228cbd019d98ca120728c64b2678fa5bb90817933d1c9cd6c0db3a526e258f07",
        "verify_pubkey": "2ELSDxLkb7dYrN6EUG69tNtULAq4Fo7WPvXyrZPmuFif",
    },
}


def test_real_genesis_cnft_verifies():
    assert V.DEFAULT_CNFT_PUBKEY == "2ELSDxLkb7dYrN6EUG69tNtULAq4Fo7WPvXyrZPmuFif"
    res = V.verify_cnft(REAL_ANCHOR, V.DEFAULT_CNFT_PUBKEY, REAL_WALLET)
    assert res["signature_valid"] is True, res.get("errors")
    assert res["valid"] is True


def test_real_genesis_cnft_tamper_fails():
    import copy
    rec = copy.deepcopy(REAL_ANCHOR)
    rec["anchor"]["tier_at_mint"] = "Platinum "  # one extra byte
    res = V.verify_cnft(rec, V.DEFAULT_CNFT_PUBKEY, REAL_WALLET)
    assert res["valid"] is False
