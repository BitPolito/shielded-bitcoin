import json
import pathlib
import pickle

import pytest

from key_derivation import params
from key_derivation.curve import ORDER, Scalar
from key_derivation.keys import SkSpend, WalletKeys, disclosure_view_keys, hkdf

SEED = bytes(range(32))


# --- Scalar -------------------------------------------------------------------

def test_scalar_rules():
    with pytest.raises(ValueError):
        Scalar(0)
    with pytest.raises(ValueError):
        Scalar.from_bytes(bytes(32))
    with pytest.raises(ValueError):
        Scalar.from_bytes(b"\x01" * 31)
    s = Scalar.from_bytes(b"\xff" * 32)  # >= ORDER: reduced
    assert 0 < s.value < ORDER
    assert Scalar.from_bytes(s.to_bytes()).value == s.value
    assert "redacted" in repr(s)


# --- Key derivation ------------------------------------------------------------

def test_deterministic_from_seed():
    a, b = WalletKeys(SEED), WalletKeys(SEED)
    assert a.sk_master == b.sk_master
    assert a.sk_spend.serialized() == b.sk_spend.serialized()
    assert a.sk_nf == b.sk_nf and a.vk_in == b.vk_in and a.vk_out == b.vk_out


def test_different_seed_different_keys():
    a, b = WalletKeys(SEED), WalletKeys(bytes(32))
    assert a.vk_in != b.vk_in
    assert a.sk_spend.serialized() != b.sk_spend.serialized()


def test_seed_length_enforced():
    for bad in (b"", bytes(31), bytes(33), b"password"):
        with pytest.raises(ValueError):
            WalletKeys(bad)


def test_domain_separation_same_input_different_outputs():
    """sk_nf and vk_in start from the same input (serialized sk_spend): without
    distinct labels they would coincide and vk_in would reveal sk_nf."""
    k = WalletKeys(SEED)
    assert k.sk_nf.to_bytes() != k.vk_in.to_bytes()
    ikm = k.sk_spend.serialized()
    labels = [params.LABEL_NF, params.LABEL_IN, params.LABEL_VIEW,
              params.LABEL_SPEND, params.LABEL_OUT, params.LABEL_MASTER]
    assert len({hkdf(ikm, label) for label in labels}) == len(labels)


def test_labels_are_distinct():
    labels = [params.LABEL_MASTER, params.LABEL_SPEND, params.LABEL_NF,
              params.LABEL_IN, params.LABEL_OUT, params.LABEL_VIEW,
              params.TAG_DIVERSIFY]
    assert len(set(labels)) == len(labels)


def test_vk_out_hangs_from_master_not_spend():
    k = WalletKeys(SEED)
    assert k.vk_out.to_bytes() == hkdf(k.sk_master.to_bytes(), params.LABEL_OUT)


def test_view_key_is_not_a_spend_key():
    k = WalletKeys(SEED)
    assert not hasattr(k.vk_in, "serialized")
    assert not isinstance(k.vk_in, SkSpend)


# --- Disclosure and secret hygiene ---------------------------------------------

def test_disclosure_exports_only_read_capabilities():
    k = WalletKeys(SEED)
    vin, vout = disclosure_view_keys(k)
    exported = {vin.to_bytes(), vout.to_bytes()}
    for secret in (SEED, k.sk_master.to_bytes(), k.sk_spend.serialized(),
                   k.sk_nf.to_bytes()):
        assert secret not in exported


def test_secrets_not_printable_or_picklable():
    k = WalletKeys(SEED)
    for obj in (k, k.sk_spend, k.sk_nf, k.vk_in, k.vk_out, k.sk_master):
        assert SEED.hex() not in repr(obj)
        assert "redacted" in repr(obj)
        with pytest.raises(TypeError):
            pickle.dumps(obj)


# --- Test vectors (the in-circuit gadget must reproduce them) ------------------

VECTORS = json.loads((pathlib.Path(__file__).parent / "vectors.json").read_text())


@pytest.mark.parametrize("v", VECTORS, ids=lambda v: v["seed"][:8])
def test_vectors(v):
    k = WalletKeys(bytes.fromhex(v["seed"]))
    assert k.sk_master.to_bytes().hex() == v["sk_master"]
    assert k.sk_spend.serialized().hex() == v["sk_spend"]
    assert k.sk_nf.to_bytes().hex() == v["sk_nf"]
    assert k.vk_in.to_bytes().hex() == v["vk_in"]
    assert k.vk_out.to_bytes().hex() == v["vk_out"]
    assert k.vk_in.sk_view().to_bytes().hex() == v["sk_view"]
