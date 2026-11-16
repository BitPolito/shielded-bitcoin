"""Address and ownership tests.

They need real group operations, which `curve.py` does not implement yet, so
they are skipped until a curve library is plugged in.
"""
import pytest

from key_derivation import params
from key_derivation.address import (Address, derive_address, derive_pk_d_from_spend,
                          diversify_hash, owns_input_note, random_diversifier)
from key_derivation.keys import WalletKeys

SEED = bytes(range(32))
D = bytes(range(11))


def _curve_available() -> bool:
    try:
        diversify_hash(D)
        return True
    except NotImplementedError:
        return False


pytestmark = pytest.mark.skipif(
    not _curve_available(), reason="curve.py point operations are not implemented"
)


def test_diversify_hash_deterministic():
    assert diversify_hash(D) == diversify_hash(D)
    assert diversify_hash(bytes(11)) != diversify_hash(D)
    with pytest.raises(ValueError):
        diversify_hash(b"short")


def test_address_roundtrip():
    k = WalletKeys(SEED)
    a = derive_address(k.vk_in, D)
    raw = a.to_bytes()
    assert len(raw) == params.DIVERSIFIER_LEN + params.POINT_LEN
    assert Address.from_bytes(raw) == a
    with pytest.raises(ValueError):
        Address.from_bytes(raw[:-1])


def test_diversified_addresses_are_distinct():
    k = WalletKeys(SEED)
    pks = {derive_address(k.vk_in, random_diversifier()).pk_d for _ in range(5)}
    assert len(pks) == 5


def test_ownership_rule_accepts_owner():
    k = WalletKeys(SEED)
    note_pk_d = derive_address(k.vk_in, D).pk_d
    assert derive_pk_d_from_spend(k.sk_spend, D) == note_pk_d
    assert owns_input_note(k.sk_spend, D, note_pk_d)


def test_ownership_rule_rejects_other_wallet():
    mine, other = WalletKeys(SEED), WalletKeys(bytes(32))
    note_pk_d = derive_address(mine.vk_in, D).pk_d
    assert not owns_input_note(other.sk_spend, D, note_pk_d)


def test_ownership_rule_rejects_wrong_diversifier():
    k = WalletKeys(SEED)
    note_pk_d = derive_address(k.vk_in, D).pk_d
    assert not owns_input_note(k.sk_spend, bytes(11), note_pk_d)
