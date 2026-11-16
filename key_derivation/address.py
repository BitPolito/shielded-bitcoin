"""Diversified addresses (paper, Sec. 6, Eq. 1).

    sk_view = ScalarFromBytes(HKDF_view(vk_in))
    G_d     = DiversifyHash(d)
    pk_d    = [sk_view] G_d
    addr_d  = (d, pk_d)

Group operations come from `curve.py`, whose point functions are interface-only
stubs until a curve library is selected.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from . import params
from .curve import Point, decode_point, encode_point, hash_to_curve, point_mul
from .keys import SkSpend, VkIn, hkdf


def _check_d(d: bytes) -> None:
    if len(d) != params.DIVERSIFIER_LEN:
        raise ValueError(f"d must be {params.DIVERSIFIER_LEN} bytes")


def diversify_hash(d: bytes) -> Point:
    """G_d = DiversifyHash(d)."""
    _check_d(d)
    return hash_to_curve(params.TAG_DIVERSIFY, d)


@dataclass(frozen=True)
class Address:
    d: bytes
    pk_d: Point

    def to_bytes(self) -> bytes:
        """Public payload: d || compressed pk_d."""
        return self.d + encode_point(self.pk_d)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Address":
        if len(data) != params.DIVERSIFIER_LEN + params.POINT_LEN:
            raise ValueError("invalid address length")
        d = data[: params.DIVERSIFIER_LEN]
        return cls(d, decode_point(data[params.DIVERSIFIER_LEN:]))


def derive_address(vk_in: VkIn, d: bytes) -> Address:
    """Address for receive path d. Only vk_in is needed."""
    _check_d(d)
    return Address(d, point_mul(vk_in.sk_view().value, diversify_hash(d)))


def random_diversifier() -> bytes:
    return os.urandom(params.DIVERSIFIER_LEN)


def derive_pk_d_from_spend(sk_spend: SkSpend, d: bytes) -> Point:
    """The circuit's ownership rule (paper, Sec. 9), written in the clear:

        vk_in^drv   := HKDF_in(BytesFromScalar(sk_spend))
        sk_view^drv := ScalarFromBytes(HKDF_view(vk_in^drv))
        pk_d^drv    := [sk_view^drv] DiversifyHash(d)

    The in-circuit gadget must produce exactly the same value.
    """
    vk_in_drv = VkIn(hkdf(sk_spend.serialized(), params.LABEL_IN))
    return derive_address(vk_in_drv, d).pk_d


def owns_input_note(sk_spend: SkSpend, note_d: bytes, note_pk_d: Point) -> bool:
    """The constraint `pk_d^drv == pk_d`, valid for INPUT notes only.

    For outputs the sender does not know the recipient's sk_spend and uses the
    pk_d of the destination address directly, with no ownership check.
    """
    return derive_pk_d_from_spend(sk_spend, note_d) == note_pk_d
