"""Edits to a signed V7 receipt: every case in testdata/v7_edit_cases.json.

The JS verifier (test/v7-edit-cases.test.js), the issuer's verify_receipt and
the SDK read the same table, so the four verifiers reach the same verdict on
the same edit.
"""

import copy
import json
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify_twzrd_receipt as V  # noqa: E402

TABLE = json.loads((Path(__file__).resolve().parents[1] / "testdata" / "v7_edit_cases.json").read_text())

# Deterministic test key (00 01 ... 1f). NOT a production key.
_SK = SigningKey(bytes(range(32)))
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED25519_L = 2**252 + 27742317777372353535851937790883648493


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return _B58_ALPHABET[0] * pad + out


TRUSTED = _b58encode(bytes(_SK.verify_key))


def _signed_v7(pre: dict) -> dict:
    leaf = V.recompute_leaf(pre)
    return {
        "version": "v7",
        "kind": "twzrd_reputation_receipt_v7",
        "preimage": copy.deepcopy(pre),
        "leaf": "0x" + leaf.hex(),
        "signature": _b58encode(_SK.sign(leaf).signature),
        "signing_pubkey": TRUSTED,
        "key_id": V.CURRENT_RECEIPT_SIGNING_KEY_ID,
        "signing_alg": "ed25519",
    }


def _s_plus_l(signature_b58: str) -> str:
    sig = V.b58decode(signature_b58)
    s = int.from_bytes(sig[32:], "little") + ED25519_L
    return _b58encode(sig[:32] + s.to_bytes(32, "little"))


def _apply_edits(receipt: dict, edits: list) -> dict:
    for edit in edits:
        if edit["op"] == "s_plus_l":
            receipt["signature"] = _s_plus_l(receipt["signature"])
            continue
        obj = receipt
        for key in edit["path"][:-1]:
            obj = obj[key]
        last = edit["path"][-1]
        if edit["op"] == "set":
            obj[last] = edit["value"]
        elif edit["op"] == "delete":
            obj.pop(last, None)
        else:
            raise ValueError(f"unknown edit op {edit['op']}")
    return receipt


def test_edit_table_bases_recompute_to_the_recorded_leaves():
    for name, pre in TABLE["base"].items():
        assert "0x" + V.recompute_leaf(pre).hex() == TABLE["base_leaf"][name], name


@pytest.mark.parametrize("case", TABLE["cases"], ids=[c["name"] for c in TABLE["cases"]])
def test_v7_edit_case(case):
    receipt = _apply_edits(_signed_v7(TABLE["base"][case["base"]]), case["edits"])
    res = V.verify(receipt, TRUSTED)
    if case["expect"] == "valid":
        assert res["valid"] is True, res.get("errors")
        return
    assert res["valid"] is False
    assert any(case["error"] in msg for msg in res["errors"]), res["errors"]


def test_card_says_the_leaf_covers_only_the_last_32_bytes_of_a_long_settlement_tx():
    long = _signed_v7(TABLE["base"]["tx"])
    long_card = V.format_bound_freshness_card(long, V.verify(long, TRUSTED))
    assert "BOUND     settlement_tx   last 32 bytes covered by Ed25519 over the signed payload" in long_card

    tx = "short-settlement-ref"
    anchor = (b"\x00" * (32 - len(tx)) + tx.encode()).hex()
    short = _signed_v7({**TABLE["base"]["tx"], "settlement_tx": tx, "settlement_anchor": anchor})
    res = V.verify(short, TRUSTED)
    assert res["valid"] is True, res.get("errors")
    short_card = V.format_bound_freshness_card(short, res)
    assert "BOUND     settlement_tx   covered by Ed25519 over the signed payload" in short_card
    assert "last 32 bytes" not in short_card
