"""PROVISIONAL profile parameters.

Everything in this file is consensus-critical: it must be frozen together with
the circuit (changing it after the trusted setup means new keys, addresses and
nullifiers).
"""

PROFILE_VERSION = b"sbtc/v1"

# Domain-separation labels for HKDF. The paper only says they are "distinct and
# fixed by the protocol": these strings are our own choice.
LABEL_MASTER = PROFILE_VERSION + b"/master"
LABEL_SPEND = PROFILE_VERSION + b"/spend"
LABEL_NF = PROFILE_VERSION + b"/nf"
LABEL_IN = PROFILE_VERSION + b"/in"
LABEL_OUT = PROFILE_VERSION + b"/out"
LABEL_VIEW = PROFILE_VERSION + b"/view"

# Tag for DiversifyHash (hash-to-curve of the diversifier).
TAG_DIVERSIFY = PROFILE_VERSION + b"/diversify"

SEED_LEN = 32          # seed_wallet: 32 uniformly random bytes
DIVERSIFIER_LEN = 11   # d: 11 bytes
KEY_LEN = 32           # output length of every HKDF call
POINT_LEN = 33         # compressed point encoding (curve-dependent, placeholder)
