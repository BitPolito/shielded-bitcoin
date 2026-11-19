"""Curve interface.

Only `Scalar` is implemented here. Every group operation is intentionally left
unimplemented: the paper does not fix the curve, and the real implementation
must come from a vetted library compatible with the proving system (e.g. a
SNARK-friendly curve such as Jubjub). Replace the stubs below, keeping the
same signatures, and the rest of the package keeps working.
"""
from __future__ import annotations

from typing import Any #variable can be of any type, useful because we haven't implemented the curve yet

# Opaque point type: its representation depends on the chosen curve, now we keep Any.
Point = Any

# Order of the prime-order group. PLACEHOLDER (secp256k1 order): Scalar needs a
# modulus, so replace this with the order of the curve actually selected.
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class Scalar:
    """Non-zero scalar modulo the group order."""

    __slots__ = ("_v",) #slots used to avoid that the class can have arbitrary attributes, now it will only accept the attribute _v, which is the value of the scalar

    def __init__(self, value: int):
        value %= ORDER
        if value == 0:
            raise ValueError("the zero scalar is not allowed")
        self._v = value

    @classmethod
    def from_bytes(cls, data: bytes) -> "Scalar":
        """ScalarFromBytes: 32 big-endian bytes reduced modulo the group order.

        The reduction rule (modular reduction vs rejection sampling) must be
        frozen in the profile.
        """
        if len(data) != 32:
            raise ValueError("exactly 32 bytes are required")
        return cls(int.from_bytes(data, "big"))

    def to_bytes(self) -> bytes:
        """BytesFromScalar: canonical 32-byte big-endian encoding."""
        return self._v.to_bytes(32, "big")

    @property #property to call the value of the scalar without using the _v attribute directly and without using the function call, so we can use scalar.value instead of scalar.value()
    def value(self) -> int:
        return self._v

    def __repr__(self) -> str:  # never expose the value, so if somebody prints a Scalar instance, it will not leak the value of the scalar but will show "Scalar(<redacted>)"
        return "Scalar(<redacted>)"


# --- Group operations: NOT IMPLEMENTED (interface only) ----------------------

def point_mul(k: int, point: Point) -> Point:
    """Scalar multiplication [k]point."""
    raise NotImplementedError("point_mul: select a curve library")


def encode_point(point: Point) -> bytes: #to convert a point to bytes
    """Canonical compressed encoding of a point."""
    raise NotImplementedError("encode_point: select a curve library")


def decode_point(data: bytes) -> Point: #to convert bytes to a point
    """Canonical decoding; must reject every non-canonical encoding."""
    raise NotImplementedError("decode_point: select a curve library")


def hash_to_curve(tag: bytes, msg: bytes) -> Point: #transform a message into a point on the curve, will be used to construct a generator Gd from d
    """Deterministic hash to a prime-order subgroup point (for DiversifyHash)."""
    raise NotImplementedError("hash_to_curve: select a curve library")
