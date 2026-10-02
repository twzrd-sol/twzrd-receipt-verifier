"""Leaf-boundary mutations for the standalone Python verifier (parity with the JS verifier).

Same mutation classes as the SDK leaf-boundary suite: freshness
forgeries, sibling swaps, envelope reorder, alternate digests, outside-leaf
fuzz. A `_V7` substring must not hide freshness from classifiers unless the
hasher actually bound it (exact TWZRD:AO_REPUTATION_RECEIPT_V7).

V7 stay cold: this file does not issue a V7 leaf.
"""

from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from nacl.signing import SigningKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify_twzrd_receipt as V  # noqa: E402

REPO = Path(__file__).resolve().parents[4]
# The receipt-lineage document lives outside this package. In a standalone
# checkout it is absent; the doc-text assertions below are then skipped.
_LINEAGE_PATH = REPO / "docs" / "RECEIPT_LINEAGE.md"
LINEAGE = _LINEAGE_PATH.read_text(encoding="utf-8") if _LINEAGE_PATH.is_file() else None

LOCKED_FRESHNESS = (
    "recheck_after_unix",
    "staleness_days",
    "score_decay_model",
)
LOCKED_REPUTATION = (
    "reputation_score",
    "reputation_confidence_bps",
    "reputation_score_version",
    "reputation_feature_window_start_unix",
    "reputation_data_quality",
)

_SK = SigningKey(bytes(range(32)))
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return _B58[0] * pad + out


TRUSTED = _b58encode(bytes(_SK.verify_key))
DECAY = "step:<=7d=1.0,<=30d=0.8,<=90d=0.5,>90d=0.25"
NOW = 1_800_000_000
KECCAK_EMPTY = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

V6_BASE = {
    "domain": "TWZRD:AO_REPUTATION_RECEIPT_V6",
    "agent_id": "11111111111111111111111111111111",
    "score": 72,
    "confidence_bps": 8000,
    "timestamp_unix": 1748736000,
    "payer": "11111111111111111111111111111111",
    "settlement_tx": "EXAMPLE-sample-receipt-no-real-settlement-tx-0001",
    "version": "v6",
    "reputation_score": 4242,
    "reputation_confidence_bps": 7500,
    "reputation_score_version": "intel_renorm_v1",
    "reputation_feature_window_start_unix": 1748000000,
    "reputation_data_quality": "high",
}

LIVE_V5 = {
    "version": "v5",
    "leaf": "0x4151f13b6e190c4ce5973e24a1336b559d26432c5c256445152334ac5cfa4755",
    "preimage": {
        "domain": "TWZRD:AO_REPUTATION_RECEIPT_V5",
        "agent_id": "4LkEFjJdXARkKx8FBx4LBFa2SvJNmjQpgGDLoJcypZUE",
        "score": 13,
        "attention_score": None,
        "confidence_bps": 6500,
        "timestamp_unix": 1780193750,
        "payer": "4LkEFjJdXARkKx8FBx4LBFa2SvJNmjQpgGDLoJcypZUE",
        "settlement_anchor": "7a676d575738466d53525a5543543558746d45725a6646316a52343543437457",
        "version": "v5",
        "reputation_score": None,
        "reputation_confidence_bps": None,
        "reputation_score_version": "intel_renorm_v1",
        "reputation_feature_window_start_unix": None,
        "reputation_data_quality": (
            "agent_executions+agent_contributions+x402_solana_payer_agg+"
            "x402_solana_merchant_agg+claims"
        ),
        "settlement_tx": (
            "5nLx1Bzn1K6PNuUytHxx4SCJafDJTCMBw1hs3B5xnfdrMDTmTYWtHbkTzgmWW8FmSRZUCT5XtmErZfF1jR45CCtW"
        ),
    },
    "signature": (
        "3g5YSTJe63DWZANqs2EBrTwrSKfC3X3kykBSyYEyQGhu5iaURVBtKk3wrNSWbjcsQgxAUtPw8VTvdpXoWCYWQrhG"
    ),
    "signing_pubkey": "9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf",
    "key_id": "twzrd-receipt-ed25519-v1",
    "signing_alg": "ed25519",
}


def _signed(pre: dict) -> dict:
    leaf = V.recompute_leaf(pre)
    return {
        "version": str(pre.get("version") or "v6"),
        "preimage": dict(pre),
        "leaf": "0x" + leaf.hex(),
        "signature": _b58encode(_SK.sign(leaf).signature),
        "signing_pubkey": TRUSTED,
        "key_id": V.CURRENT_RECEIPT_SIGNING_KEY_ID,
        "signing_alg": "ed25519",
    }


def _with_freshness(pre: dict, recheck: int, days: int = 3) -> dict:
    return dict(pre, recheck_after_unix=recheck, staleness_days=days, score_decay_model=DECAY)


def _clone(rec: dict) -> dict:
    return deepcopy(rec)


def _due(pre: dict, now: int) -> bool:
    rec = pre.get("recheck_after_unix")
    return rec is not None and now >= rec


def _hasher_bound_freshness(pre: dict) -> bool:
    return pre.get("domain") == V.REPUTATION_V7_DOMAIN.decode()


def assert_no_trusted_due(res: dict, rec: dict, now: int, label: str) -> None:
    """due may flip; hasher-bound freshness must not be claimed unless it is."""
    pre = rec.get("preimage") or {}
    card = V.format_bound_freshness_card(rec, res)
    if _hasher_bound_freshness(pre) and res.get("leaf_valid") is True:
        return
    assert res.get("freshness_unauthenticated") is True, f"{label}: freshness_unauthenticated"
    assert res.get("leaf_version", "v5") != "v7", f"{label}: leaf_version must not be v7"
    if _due(pre, now):
        for name in LOCKED_FRESHNESS:
            if pre.get(name) is not None:
                assert name in res["unauthenticated_fields"], f"{label}: missing {name}"
        assert "covered by the V7 leaf binding" not in card, f"{label}: card claimed V7 bind"


def test_lineage_doc_tuples_match_standalone_verifier():
    def tup(name: str) -> tuple[str, ...]:
        import re

        src = (Path(__file__).resolve().parents[1] / "verify_twzrd_receipt.py").read_text()
        match = re.search(rf"{name}\s*=\s*\((.*?)\)", src, flags=re.S)
        assert match, name
        return tuple(re.findall(r'"([^"]+)"', match.group(1)))

    assert tup("REPUTATION_PROVENANCE_FIELDS") == LOCKED_REPUTATION == V.REPUTATION_PROVENANCE_FIELDS
    assert tup("FRESHNESS_UNAUTHENTICATED_FIELDS") == LOCKED_FRESHNESS == V.FRESHNESS_UNAUTHENTICATED_FIELDS
    if LINEAGE is not None:
        assert "There is no V1 to V7 ladder" in LINEAGE


def test_keccak256_not_sha3():
    if LINEAGE is not None:
        assert "keccak256 (the Ethereum variant), **not** SHA3" in LINEAGE
    assert V.keccak256(b"").hex() == KECCAK_EMPTY
    assert hashlib.sha3_256(b"").hexdigest() != KECCAK_EMPTY


def test_v5_unauthenticated_algorithm():
    pre = _with_freshness(LIVE_V5["preimage"], LIVE_V5["preimage"]["timestamp_unix"] + 3 * 86400)
    rec = {**LIVE_V5, "preimage": pre}
    res = V.verify(rec, LIVE_V5["signing_pubkey"])
    assert res["leaf_valid"] is True
    assert res.get("leaf_version", "v5") == "v5"
    expected = [n for n in LOCKED_FRESHNESS if pre.get(n) is not None]
    expected += [n for n in LOCKED_REPUTATION if pre.get(n) is not None]
    assert set(res["unauthenticated_fields"]) == set(expected)


def test_v6_unauthenticated_algorithm():
    pre = _with_freshness(V6_BASE, V6_BASE["timestamp_unix"] + 7 * 86400, 7)
    rec = _signed(pre)
    rec["signature"] = "x"
    rec["signing_pubkey"] = None
    res = V.verify(rec, TRUSTED)
    assert res["leaf_valid"] is True
    assert res.get("leaf_version", "v6") == "v6"
    assert set(res["unauthenticated_fields"]) == set(LOCKED_FRESHNESS)


def test_forged_freshness_on_live_v5_is_untrusted():
    forged = _clone(LIVE_V5)
    forged["preimage"]["recheck_after_unix"] = NOW - 1
    forged["preimage"]["staleness_days"] = 99
    forged["preimage"]["score_decay_model"] = "forged-decay"
    res = V.verify(forged, forged["signing_pubkey"])
    assert res["leaf_valid"] is True
    assert res["signature_valid"] is True
    assert res["valid"] is True
    for name in LOCKED_FRESHNESS:
        assert name in res["unauthenticated_fields"]
    assert_no_trusted_due(res, forged, NOW, "live V5 freshness forge")


def test_forged_freshness_on_signed_v6_keeps_leaf():
    honest_recheck = V6_BASE["timestamp_unix"] + 7 * 86400
    rec = _signed(_with_freshness(V6_BASE, honest_recheck, 7))
    assert _due(rec["preimage"], honest_recheck - 1) is False
    forged = _clone(rec)
    forged["preimage"]["recheck_after_unix"] = NOW - 60
    forged["preimage"]["staleness_days"] = 1
    forged["preimage"]["score_decay_model"] = "PWNED"
    res = V.verify(forged, TRUSTED)
    assert res["leaf_valid"] is True
    assert res["signature_valid"] is True
    assert res["valid"] is True
    assert forged["leaf"] == rec["leaf"]
    assert _due(forged["preimage"], NOW) is True
    assert_no_trusted_due(res, forged, NOW, "signed V6 freshness forge")


@pytest.mark.parametrize("field", LOCKED_FRESHNESS)
def test_flipping_one_freshness_field_stays_untrusted(field: str):
    rec = _signed(V6_BASE)
    mutated = _clone(rec)
    if field == "score_decay_model":
        mutated["preimage"][field] = "x"
    elif field == "staleness_days":
        mutated["preimage"][field] = 1
    else:
        mutated["preimage"][field] = NOW - 1
    res = V.verify(mutated, TRUSTED)
    assert res["leaf_valid"] is True
    assert field in res["unauthenticated_fields"]
    assert_no_trusted_due(res, mutated, NOW, field)


def test_decay_byte_flip_is_outside_leaf():
    rec = _signed(_with_freshness(V6_BASE, NOW + 100))
    mutated = _clone(rec)
    raw = bytearray(mutated["preimage"]["score_decay_model"].encode())
    raw[0] ^= 0xFF
    mutated["preimage"]["score_decay_model"] = raw.decode("latin1")
    res = V.verify(mutated, TRUSTED)
    assert res["leaf_valid"] is True
    assert_no_trusted_due(res, mutated, NOW, "decay byte flip")


def test_freshness_sibling_swap_can_flip_due_untrusted():
    recheck = NOW + 500
    rec = _signed(_with_freshness(V6_BASE, recheck, 7))
    swapped = _clone(rec)
    swapped["preimage"]["recheck_after_unix"] = swapped["preimage"]["staleness_days"]
    swapped["preimage"]["staleness_days"] = recheck
    res = V.verify(swapped, TRUSTED)
    assert res["leaf_valid"] is True
    assert _due(swapped["preimage"], NOW) is True
    assert_no_trusted_due(res, swapped, NOW, "freshness sibling swap")


def test_bound_score_reputation_sibling_breaks_leaf():
    rec = _signed(_with_freshness(V6_BASE, NOW - 1))
    swapped = _clone(rec)
    swapped["preimage"]["score"] = rec["preimage"]["reputation_score"]
    swapped["preimage"]["reputation_score"] = rec["preimage"]["score"]
    res = V.verify(swapped, TRUSTED)
    assert res["leaf_valid"] is False
    assert res["valid"] is False
    assert_no_trusted_due(res, swapped, NOW, "bound sibling swap")


def test_unused_settlement_anchor_is_outside_leaf():
    rec = _signed(_with_freshness(V6_BASE, NOW - 1))
    mutated = _clone(rec)
    mutated["preimage"]["settlement_anchor"] = "TAMPERED-UNUSED-ANCHOR"
    res = V.verify(mutated, TRUSTED)
    assert res["leaf_valid"] is True
    assert res["signature_valid"] is True
    assert_no_trusted_due(res, mutated, NOW, "unused anchor")


def test_envelope_reorder_does_not_change_leaf():
    rec = _signed(_with_freshness(V6_BASE, NOW + 10))
    reordered = json.loads(
        json.dumps(
            {
                "signing_alg": rec["signing_alg"],
                "signature": rec["signature"],
                "key_id": rec["key_id"],
                "preimage": {
                    "score_decay_model": rec["preimage"]["score_decay_model"],
                    "domain": rec["preimage"]["domain"],
                    "recheck_after_unix": rec["preimage"]["recheck_after_unix"],
                    "payer": rec["preimage"]["payer"],
                    "score": rec["preimage"]["score"],
                    "staleness_days": rec["preimage"]["staleness_days"],
                    "agent_id": rec["preimage"]["agent_id"],
                    "confidence_bps": rec["preimage"]["confidence_bps"],
                    "timestamp_unix": rec["preimage"]["timestamp_unix"],
                    "settlement_tx": rec["preimage"]["settlement_tx"],
                    "version": rec["preimage"]["version"],
                    "reputation_score": rec["preimage"]["reputation_score"],
                    "reputation_confidence_bps": rec["preimage"]["reputation_confidence_bps"],
                    "reputation_score_version": rec["preimage"]["reputation_score_version"],
                    "reputation_feature_window_start_unix": rec["preimage"][
                        "reputation_feature_window_start_unix"
                    ],
                    "reputation_data_quality": rec["preimage"]["reputation_data_quality"],
                },
                "leaf": rec["leaf"],
                "version": rec["version"],
                "signing_pubkey": rec["signing_pubkey"],
            }
        )
    )
    res = V.verify(reordered, TRUSTED)
    assert res["leaf_valid"] is True
    assert res["signature_valid"] is True
    assert reordered["leaf"] == rec["leaf"]
    assert_no_trusted_due(res, reordered, NOW, "envelope reorder")


def test_injected_envelope_due_flags_do_not_classify_as_freshness():
    rec = _signed(V6_BASE)
    injected = {
        **rec,
        "due": True,
        "trusted": True,
        "untrusted": False,
        "shouldRecheckTrusted": True,
        "recheck_after_unix": 1,
    }
    res = V.verify(injected, TRUSTED)
    assert "recheck_after_unix" not in res["unauthenticated_fields"]
    assert _due(injected["preimage"], NOW) is False
    assert_no_trusted_due(res, injected, NOW, "envelope due injection")


def test_envelope_freshness_does_not_flip_due():
    rec = _signed(V6_BASE)
    injected = {**rec, "recheck_after_unix": 1, "staleness_days": 1, "score_decay_model": DECAY}
    res = V.verify(injected, TRUSTED)
    assert _due(injected["preimage"], NOW) is False
    assert "recheck_after_unix" not in res["unauthenticated_fields"]
    assert_no_trusted_due(res, injected, NOW, "envelope freshness")


@pytest.mark.parametrize(
    "kind",
    ["zero digest", "keccak of JSON preimage", "sha3-256 of leaf bytes"],
)
def test_alternate_digest_fails_and_cannot_mint_trusted_due(kind: str):
    rec = _signed(_with_freshness(V6_BASE, NOW - 1))
    if kind == "zero digest":
        leaf = "0x" + "00" * 32
    elif kind == "keccak of JSON preimage":
        leaf = "0x" + V.keccak256(json.dumps(rec["preimage"]).encode()).hex()
    else:
        body = bytes.fromhex(str(rec["leaf"]).removeprefix("0x"))
        leaf = "0x" + hashlib.sha3_256(body).hexdigest()
    mutated = {**rec, "leaf": leaf}
    res = V.verify(mutated, TRUSTED)
    assert res["leaf_valid"] is False
    assert res["valid"] is False
    assert _due(mutated["preimage"], NOW) is True
    assert_no_trusted_due(res, mutated, NOW, kind)


def test_v6_v7_domain_suffix_cannot_hide_freshness():
    """Honesty: `_V7` substring must not claim V7 binding.

    Standalone hasher allowlists exact domains (unlike the SDK remap), so the
    leaf is invalid. Classifiers must still list freshness and must not report
    leaf_version=v7 or a V7-bound card.
    """
    rec = _signed(_with_freshness(V6_BASE, NOW - 1))
    spoofed = _clone(rec)
    spoofed["preimage"]["domain"] = "TWZRD:AO_REPUTATION_RECEIPT_V6_V7"
    res = V.verify(spoofed, TRUSTED)
    assert res["leaf_valid"] is False
    assert res["leaf_version"] == "v6"
    assert res["freshness_unauthenticated"] is True
    for name in LOCKED_FRESHNESS:
        assert name in res["unauthenticated_fields"], name
    card = V.format_bound_freshness_card(spoofed, res)
    assert "covered by the V7 leaf binding" not in card
    assert _due(spoofed["preimage"], NOW) is True
    assert_no_trusted_due(res, spoofed, NOW, "V6_V7 domain spoof")


def test_classifier_source_does_not_use_v7_substring():
    src = (Path(__file__).resolve().parents[1] / "verify_twzrd_receipt.py").read_text()
    stripped = src.replace("TWZRD:AO_REPUTATION_RECEIPT_V7", "")
    assert 'includes("_V7")' not in stripped
    assert "includes('_V7')" not in stripped
    assert '"_V7" in' not in stripped
    assert "'_V7' in" not in stripped


def test_seeded_fuzz_outside_leaf_never_trusted_due():
    rec = _signed(_with_freshness(V6_BASE, NOW + 999, 7))

    def mulberry32(seed: int):
        state = seed & 0xFFFFFFFF

        def rng() -> float:
            nonlocal state
            state = (state + 0x6D2B79F5) & 0xFFFFFFFF
            t = ((state ^ (state >> 15)) * (1 | state)) & 0xFFFFFFFF
            t = ((t + (((t ^ (t >> 7)) * (61 | t)) & 0xFFFFFFFF)) ^ t) & 0xFFFFFFFF
            return ((t ^ (t >> 14)) & 0xFFFFFFFF) / 4294967296

        return rng

    rng = mulberry32(0x26222621)
    for i in range(48):
        mutated = _clone(rec)
        pick = int(rng() * 6)
        if pick == 0:
            mutated["preimage"]["recheck_after_unix"] = int(rng() * NOW * 2)
        elif pick == 1:
            mutated["preimage"]["staleness_days"] = int(rng() * 400)
        elif pick == 2:
            mutated["preimage"]["score_decay_model"] = f"fuzz-{i}-{rng():.6f}"
        elif pick == 3:
            mutated["preimage"]["settlement_anchor"] = f"anchor-fuzz-{i}"
        elif pick == 4:
            mutated["version"] = "v7" if rng() > 0.5 else "v0"
            mutated["extra"] = "injected"
        else:
            mutated["leaf"] = "0x" + V.keccak256(f"alt-{i}".encode()).hex()
        now = int(rng() * NOW * 2)
        res = V.verify(mutated, TRUSTED)
        assert_no_trusted_due(res, mutated, now, f"fuzz {i}")
        if pick <= 3:
            assert res["leaf_valid"] is True, f"fuzz {i} leaf"


@pytest.mark.parametrize(
    "field",
    ["score", "timestamp_unix", "reputation_score", "confidence_bps", "agent_id"],
)
def test_bound_field_mutation_breaks_v6_leaf(field: str):
    rec = _signed(_with_freshness(V6_BASE, NOW - 1))
    mutated = _clone(rec)
    if field == "agent_id":
        mutated["preimage"][field] = "22222222222222222222222222222222"
    else:
        mutated["preimage"][field] = int(mutated["preimage"][field]) + 1
    res = V.verify(mutated, TRUSTED)
    assert res["leaf_valid"] is False
    assert res["valid"] is False
    assert_no_trusted_due(res, mutated, NOW, f"bound {field}")
