"""`freshness_bound` in the trusted-bits block and the card's FRESHNESS lines
state one fact, so they must agree on every receipt.

Through 1.4.5 a verified V7 receipt printed `covered by the V7 leaf binding`
three times and then `freshness_bound  : false`. The bit is now read from the
same function as the card. `trusted_due` and `trusted_allow` stay false
everywhere. test/freshness-bound.test.js holds the JS verifier to the same
cases.
"""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify_twzrd_receipt as V  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "verify_twzrd_receipt.py"
TABLE = json.loads((ROOT / "testdata" / "v7_edit_cases.json").read_text())
FRESHNESS = ("recheck_after_unix", "staleness_days", "score_decay_model")
LEAF_BOUND_NOTE = "covered by the V7 leaf binding"
NOT_BOUND_NOTE = "present, NOT signature-bound; do not treat as proof"

# Deterministic test key (00 01 ... 1f). NOT a production key.
_SK = SigningKey(bytes(range(32)))
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED25519_L = 2**252 + 27742317777372353535851937790883648493


def _bits(bound: bool) -> str:
    return "\n".join((
        "trusted_due      : false",
        "trusted_allow    : false",
        f"freshness_bound  : {'true' if bound else 'false'}",
    ))


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


def _v6_example() -> dict:
    env = json.loads((ROOT / "testdata" / "v6_example.json").read_text())
    return copy.deepcopy(env.get("twzrd_receipt") or env)


def _card_freshness(card: str):
    """What the card says about freshness: 'bound', 'unbound', or None when it lists no freshness field."""
    lines = [line for line in card.split("\n") if line.startswith("FRESHNESS ")]
    if not lines:
        return None
    bound = sum(1 for line in lines if line.endswith(LEAF_BOUND_NOTE))
    assert bound in (0, len(lines)), f"FRESHNESS lines disagree with each other:\n{card}"
    return "bound" if bound else "unbound"


def _run_cli(receipt: dict, tmp_path, *extra: str) -> subprocess.CompletedProcess:
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(CLI), "--receipt", str(path), "--pubkey", TRUSTED, *extra],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("name", sorted(TABLE["base"]))
def test_verified_v7_reads_freshness_bound_true_under_matching_freshness_lines(name):
    receipt = _signed_v7(TABLE["base"][name])
    res = V.verify(receipt, TRUSTED)
    assert res["valid"] is True
    assert res["freshness_unauthenticated"] is False
    assert V.freshness_leaf_bound(res) is True
    assert V.format_trusted_bits(receipt, res) == _bits(True)
    card = V.format_bound_freshness_card(receipt, res)
    for field in FRESHNESS:
        assert f"FRESHNESS {field}   {LEAF_BOUND_NOTE}" in card
    assert _card_freshness(card) == "bound"


def test_every_v7_edit_case_bit_follows_the_verdict_and_agrees_with_the_card():
    assert len(TABLE["cases"]) >= 30
    bound = 0
    for case in TABLE["cases"]:
        receipt = _apply_edits(_signed_v7(TABLE["base"][case["base"]]), case["edits"])
        res = V.verify(receipt, TRUSTED)
        valid = res.get("valid") is True
        card = V.format_bound_freshness_card(receipt, res)
        # An edited receipt is bound exactly when it still verifies.
        assert V.format_trusted_bits(receipt, res) == _bits(valid), case["name"]
        said = _card_freshness(card)
        if said is not None:
            assert said == ("bound" if valid else "unbound"), case["name"]
        if not valid:
            assert LEAF_BOUND_NOTE not in card, case["name"]
        bound += 1 if valid else 0
    # The table is mostly refusals; make sure the loop saw them.
    assert bound < len(TABLE["cases"])


def test_verified_v6_stays_false_whatever_its_json_claims():
    receipt = _v6_example()
    receipt["freshness_bound"] = True
    receipt["preimage"]["freshness_bound"] = True
    receipt["preimage"]["trusted_allow"] = True
    receipt["preimage"]["trusted_due"] = True
    res = V.verify(receipt, receipt["signing_pubkey"])
    assert res["valid"] is True
    assert V.freshness_leaf_bound(res) is False
    assert V.format_trusted_bits(receipt, res) == _bits(False)
    assert _card_freshness(V.format_bound_freshness_card(receipt, res)) == "unbound"


def test_v7_domain_written_onto_a_v6_signature_stays_false():
    receipt = _v6_example()
    receipt["preimage"] = {**receipt["preimage"], "domain": "TWZRD:AO_REPUTATION_RECEIPT_V7", "version": "v7"}
    receipt["kind"] = "twzrd_reputation_receipt_v7"
    receipt["version"] = "v7"
    res = V.verify(receipt, receipt["signing_pubkey"])
    assert res["valid"] is False
    assert V.format_trusted_bits(receipt, res) == _bits(False)
    assert LEAF_BOUND_NOTE not in V.format_bound_freshness_card(receipt, res)


@pytest.mark.parametrize(
    "res",
    [
        None,
        {},
        {"valid": True},
        {"valid": True, "freshness_unauthenticated": True},
        {"valid": True, "freshness_unauthenticated": None},
        {"valid": True, "freshness_unauthenticated": 0},
        {"valid": False, "freshness_unauthenticated": False},
        {"freshness_unauthenticated": False},
    ],
)
def test_bit_is_read_from_a_complete_verification_result_only(res):
    v7 = _signed_v7(TABLE["base"]["tx"])
    assert V.freshness_leaf_bound(res) is False
    assert V.format_trusted_bits(v7, res) == _bits(False)
    assert V.format_trusted_bits() == _bits(False)


def test_other_two_bits_never_move():
    v7 = _signed_v7(TABLE["base"]["tx"])
    loud = {"valid": True, "freshness_unauthenticated": False, "trusted_allow": True, "trusted_due": True}
    assert V.format_trusted_bits(v7, loud) == _bits(True)


def test_cli_verified_v7_prints_freshness_bound_true_once(tmp_path):
    proc = _run_cli(_signed_v7(TABLE["base"]["tx"]), tmp_path, "--self-test")
    out = proc.stdout
    assert proc.returncode == 0, out + proc.stderr
    assert "RESULT           : VALID" in out
    assert out.count(LEAF_BOUND_NOTE) == 3
    assert out.count("freshness_bound  : true") == 1
    assert "freshness_bound  : false" not in out
    assert "trusted_due      : false" in out
    assert "trusted_allow    : false" in out
    assert "trusted_due      : true" not in out
    assert "trusted_allow    : true" not in out


def test_cli_edited_v7_prints_invalid_and_freshness_bound_false(tmp_path):
    receipt = _signed_v7(TABLE["base"]["tx"])
    receipt["preimage"]["score"] = (receipt["preimage"].get("score") or 0) + 1
    proc = _run_cli(receipt, tmp_path)
    out = proc.stdout
    assert proc.returncode == 1, out + proc.stderr
    assert "RESULT           : INVALID" in out
    assert "freshness_bound  : false" in out
    assert "freshness_bound  : true" not in out
    assert LEAF_BOUND_NOTE not in out
    assert f"FRESHNESS recheck_after_unix   {NOT_BOUND_NOTE}" in out


def test_cli_v7_refused_for_age_prints_freshness_bound_false(tmp_path):
    proc = _run_cli(_signed_v7(TABLE["base"]["tx"]), tmp_path, "--max-age", "1")
    out = proc.stdout
    assert proc.returncode == 1, out + proc.stderr
    assert "RESULT           : INVALID" in out
    assert "freshness_bound  : false" in out
    assert LEAF_BOUND_NOTE not in out
