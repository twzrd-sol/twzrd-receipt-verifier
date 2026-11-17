"""Scope of the legacy v1 receipt keys, and the type of ``leaf``.

Rule: a legacy key verifies a receipt only when the leaf is V5 or V6 and the
signed preimage timestamp_unix is at or before the key-rotation cutoff. A V7
receipt is checked against the current key only. A caller-pinned key is never
widened with legacy keys. ``leaf`` must be a string.

test/legacy-key-scope.test.js holds the same cases for the JS verifier. The
legacy seeds are not used: a throwaway key stands in for a legacy key by being
appended to the in-memory legacy list for the duration of each case.
"""

import copy
import json
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify_twzrd_receipt as V  # noqa: E402

# 2026-08-28T23:59:59Z. Kept as a literal so a change to the constant is a
# deliberate edit in both places.
CUTOFF = 1787961599

_TESTDATA = Path(__file__).resolve().parents[1] / "testdata"
TABLE = json.loads((_TESTDATA / "v7_edit_cases.json").read_text())
V6_FIXTURE = json.loads((_TESTDATA / "v6_example.json").read_text())["twzrd_receipt"]

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return _B58_ALPHABET[0] * pad + out


# Throwaway keys. NOT production keys.
STANDIN = SigningKey(bytes([9]) * 32)
STANDIN_PUB = _b58encode(bytes(STANDIN.verify_key))
PINNED = SigningKey(bytes([11]) * 32)
PINNED_PUB = _b58encode(bytes(PINNED.verify_key))


@pytest.fixture()
def standin_legacy_key(monkeypatch):
    monkeypatch.setattr(V, "LEGACY_RECEIPT_PUBKEYS", (*V.LEGACY_RECEIPT_PUBKEYS, STANDIN_PUB))


def _sign(pre: dict, key: SigningKey, **envelope) -> dict:
    leaf = V.recompute_leaf(pre)
    return {
        "preimage": copy.deepcopy(pre),
        "leaf": "0x" + leaf.hex(),
        "signature": _b58encode(key.sign(leaf).signature),
        "signing_alg": "ed25519",
        **envelope,
    }


def _v7_pre() -> dict:
    return copy.deepcopy(TABLE["base"]["tx"])


def _v6_pre(ts: int) -> dict:
    return {**copy.deepcopy(V6_FIXTURE["preimage"]), "timestamp_unix": ts}


def _v5_pre(ts: int) -> dict:
    return {**_v6_pre(ts), "domain": "TWZRD:AO_REPUTATION_RECEIPT_V5", "version": "v5"}


V7_ENV = {"version": "v7", "kind": "twzrd_reputation_receipt_v7"}
LEGACY_ID = {"key_id": V.LEGACY_RECEIPT_SIGNING_KEY_ID}

# name, receipt builder, expected valid. Mirrored in test/legacy-key-scope.test.js.
CASES = [
    ("v7 legacy key_id", lambda: _sign(_v7_pre(), STANDIN, **V7_ENV, **LEGACY_ID, signing_pubkey=STANDIN_PUB), False),
    ("v7 legacy key_id, no signing_pubkey", lambda: _sign(_v7_pre(), STANDIN, **V7_ENV, **LEGACY_ID), False),
    ("v7 no key_id, legacy signing_pubkey", lambda: _sign(_v7_pre(), STANDIN, **V7_ENV, signing_pubkey=STANDIN_PUB), False),
    ("v7 no key_id, no signing_pubkey", lambda: _sign(_v7_pre(), STANDIN, **V7_ENV), False),
    ("v6 legacy key_id at cutoff", lambda: _sign(_v6_pre(CUTOFF), STANDIN, version="v6", **LEGACY_ID, signing_pubkey=STANDIN_PUB), True),
    ("v6 legacy key_id after cutoff", lambda: _sign(_v6_pre(CUTOFF + 1), STANDIN, version="v6", **LEGACY_ID, signing_pubkey=STANDIN_PUB), False),
    ("v6 no key_id at cutoff", lambda: _sign(_v6_pre(CUTOFF), STANDIN, version="v6"), True),
    ("v6 no key_id after cutoff", lambda: _sign(_v6_pre(CUTOFF + 1), STANDIN, version="v6"), False),
    ("v6 no key_id after cutoff, legacy signing_pubkey", lambda: _sign(_v6_pre(CUTOFF + 1), STANDIN, version="v6", signing_pubkey=STANDIN_PUB), False),
    ("v5 legacy key_id at cutoff", lambda: _sign(_v5_pre(CUTOFF), STANDIN, version="v5", **LEGACY_ID, signing_pubkey=STANDIN_PUB), True),
    ("v5 legacy key_id after cutoff", lambda: _sign(_v5_pre(CUTOFF + 1), STANDIN, version="v5", **LEGACY_ID, signing_pubkey=STANDIN_PUB), False),
    ("v5 no key_id after cutoff", lambda: _sign(_v5_pre(CUTOFF + 1), STANDIN, version="v5"), False),
]


@pytest.mark.parametrize("name,build,expected", CASES, ids=[c[0] for c in CASES])
def test_legacy_key_scope(standin_legacy_key, name, build, expected):
    res = V.verify(build(), V.CURRENT_RECEIPT_PUBKEY)
    assert res["valid"] is expected, res["errors"]
    if not expected:
        assert res["signature_valid"] is False


def test_cutoff_constant():
    assert V.LEGACY_RECEIPT_KEY_CUTOFF_UNIX == CUTOFF


def test_published_v6_sample_still_verifies_with_default_key():
    res = V.verify(copy.deepcopy(V6_FIXTURE), V.CURRENT_RECEIPT_PUBKEY)
    assert res["valid"] is True, res["errors"]
    assert res["leaf_version"] == "v6"


def test_caller_pinned_key_is_not_widened_with_legacy_keys(standin_legacy_key):
    receipt = _sign(_v6_pre(CUTOFF), STANDIN, version="v6", **LEGACY_ID, signing_pubkey=STANDIN_PUB)
    no_embedded = _sign(_v6_pre(CUTOFF), STANDIN, version="v6", **LEGACY_ID)
    no_key_id = _sign(_v6_pre(CUTOFF), STANDIN, version="v6")
    for r in (receipt, no_embedded, no_key_id):
        res = V.verify(r, PINNED_PUB)
        assert res["valid"] is False
        assert res["signature_valid"] is False
    # The pinned key itself still verifies what it signed, whatever the key_id says.
    own = _sign(_v6_pre(CUTOFF + 1), PINNED, version="v6", **LEGACY_ID, signing_pubkey=PINNED_PUB)
    assert V.verify(own, PINNED_PUB)["valid"] is True


@pytest.mark.parametrize(
    "build",
    [
        lambda: _sign(_v7_pre(), PINNED, **V7_ENV, key_id=V.CURRENT_RECEIPT_SIGNING_KEY_ID, signing_pubkey=PINNED_PUB),
        lambda: _sign(_v6_pre(CUTOFF), PINNED, version="v6", key_id=V.CURRENT_RECEIPT_SIGNING_KEY_ID, signing_pubkey=PINNED_PUB),
    ],
    ids=["v7", "v6"],
)
def test_leaf_must_be_a_string(build):
    good = build()
    assert V.verify(good, PINNED_PUB)["valid"] is True
    for bad in ([good["leaf"]], {"leaf": good["leaf"]}, 7, True):
        res = V.verify({**good, "leaf": bad}, PINNED_PUB)
        assert res["valid"] is False
        assert res["leaf_valid"] is False
        assert "leaf must be a string" in res["errors"], res["errors"]
