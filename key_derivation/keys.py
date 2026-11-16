"""Wallet key hierarchy (paper, Sec. 6, Table 1).

    seed_wallet
      └─ sk_master = HKDF_master(seed)
           ├─ sk_spend = ScalarFromBytes(HKDF_spend(sk_master))   [SECRET]
           │    ├─ sk_nf = HKDF_nf(BytesFromScalar(sk_spend))
           │    └─ vk_in = HKDF_in(BytesFromScalar(sk_spend))     [read-only]
           │         └─ sk_view = ScalarFromBytes(HKDF_view(vk_in))
           └─ vk_out = HKDF_out(sk_master)                        [read-only]

Note: Python gives no guarantee of zeroing memory; real zeroization requires
the production implementation (e.g. Rust with the zeroize crate).
"""
from __future__ import annotations

import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import params
from .curve import Scalar


def hkdf(ikm: bytes, label: bytes) -> bytes:
    """HKDF-SHA256 with no salt and the label in the `info` parameter.

    The paper does not say whether the label goes in `info` or in `salt`;
    this choice must be frozen in the profile.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=params.KEY_LEN,
        salt=None,
        info=label,
    ).derive(ikm)


class _Secret:
    """Base class for secret values: redacted repr, no accidental pickling."""

    __slots__ = ("_b",)

    def __init__(self, data: bytes):
        if len(data) != params.KEY_LEN:
            raise ValueError("invalid key length")
        self._b = bytes(data)

    def to_bytes(self) -> bytes:
        return self._b

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"

    def __eq__(self, other: object) -> bool:
        # Constant-time comparison.
        return type(other) is type(self) and hmac.compare_digest(
            self._b, other._b  # type: ignore[attr-defined]
        )

    __hash__ = None  # type: ignore[assignment]

    def __reduce__(self):
        raise TypeError("serializing secrets is not allowed")


# Distinct types: a VkIn can never be passed where an SkNf is expected, etc.
class SkMaster(_Secret):
    """Root secret derived from the seed."""


class SkNf(_Secret):
    """Nullifier secret. Never disclosed."""


class VkIn(_Secret):
    """READ-ONLY capability: detects and decrypts received notes."""

    def sk_view(self) -> Scalar:
        return Scalar.from_bytes(hkdf(self._b, params.LABEL_VIEW))


class VkOut(_Secret):
    """READ-ONLY capability: recovers the history of sent payments."""


class SkSpend:
    """Spend authority. The only object able to authorize a spend."""

    __slots__ = ("_s",)

    def __init__(self, scalar: Scalar):
        self._s = scalar

    @property
    def scalar(self) -> Scalar:
        return self._s

    def serialized(self) -> bytes:
        """BytesFromScalar(sk_spend): input of the downstream derivations."""
        return self._s.to_bytes()

    def __repr__(self) -> str:
        return "SkSpend(<redacted>)"

    def __reduce__(self):
        raise TypeError("serializing secrets is not allowed")


class WalletKeys:
    """All capabilities derived from a single seed."""

    __slots__ = ("sk_master", "sk_spend", "sk_nf", "vk_in", "vk_out")

    def __init__(self, seed: bytes):
        if len(seed) != params.SEED_LEN:
            raise ValueError(f"the seed must be {params.SEED_LEN} bytes")
        self.sk_master = SkMaster(hkdf(seed, params.LABEL_MASTER))
        self.sk_spend = SkSpend(
            Scalar.from_bytes(hkdf(self.sk_master.to_bytes(), params.LABEL_SPEND))
        )
        spend_ser = self.sk_spend.serialized()
        self.sk_nf = SkNf(hkdf(spend_ser, params.LABEL_NF))
        self.vk_in = VkIn(hkdf(spend_ser, params.LABEL_IN))
        # vk_out hangs from sk_master, NOT from sk_spend: a holder of vk_out
        # cannot reach the spend key.
        self.vk_out = VkOut(hkdf(self.sk_master.to_bytes(), params.LABEL_OUT))

    def __repr__(self) -> str:
        return "WalletKeys(<redacted>)"

    def __reduce__(self):
        raise TypeError("serializing secrets is not allowed")


def disclosure_view_keys(keys: WalletKeys) -> tuple[VkIn, VkOut]:
    """Single export point for audits: returns ONLY read-only capabilities.

    Never the seed, sk_spend or sk_nf (paper, Sec. 7).
    """
    return keys.vk_in, keys.vk_out
