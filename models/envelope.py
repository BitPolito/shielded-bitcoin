
from dataclasses import dataclass
from models.header import HEADER
@dataclass(frozen=True) #frozen=True makes the dataclass immutable after creation, which is important for security and integrity of the envelope data
#it is not a problem for us in case of blockchain reorganization because in that case we will create new envelopes from the replay state, not modify the already existent ones
class Envelope:
    """
    Represents a Shielded Bitcoin transfer envelope.

    e = (Body(e), proof(e))

    Paper references:
        - Section 5, pages 9-10: describes note outputs and their public representation.
        - Section 8: defines the anchor mechanism.
        - Section 9, page 15: defines public nullifiers.
        - Appendix A.3, page 43: defines the logical envelope body and its ordered fields.
        - Appendix A.3, page 43: provides concrete field sizes for the estimated 2-input/2-output implementation profile.

    Implementation checks:
        - Field types and structural consistency are enforced.
        - The number of note ciphertexts must match the number of ephemeral public keys.
        - Fixed byte lengths follow the concrete 2-input/2-output profile used by this implementation and must not be interpreted as universal across all possible arities.
        - Immutability is an implementation design choice.
    """

    header: bytes
    hanchor: int
    nullifiers: tuple[bytes, ...] #these structures must be immutable after validation, so we use tuples instead of lists
    ephemeral_public_keys: tuple[bytes, ...]
    note_ciphertexts: tuple[bytes, ...]
    recovery_ciphertext: bytes
    proof: bytes

    def __post_init__(self):

        # Header
        if not isinstance(self.header, bytes):
            raise TypeError("Header must be bytes.")

        if len(self.header) != 6:
            raise ValueError("Header must be exactly 6 bytes.")

        # Validate the canonical protocol header.
        # The paper defines the logical header ("btc", 1, 0x01).
        # Our implementation encodes the version using 2 bytes
        # (uint16 little-endian), preserving the 6-byte header
        # assumed in Appendix A.4.
        #
        # Only the currently supported protocol version and
        # transfer type are accepted.

        if self.header != HEADER:
            raise ValueError(
                "Unsupported or invalid Shielded Bitcoin header."
            )
    
        # Anchor height
        if type(self.hanchor) is not int:
            raise TypeError("Anchor height must be an integer.")

        if not 0 <= self.hanchor < 2**32:
            raise ValueError("Anchor height must fit in uint32.")

        # Vector types
        if not isinstance(self.nullifiers, tuple):
            raise TypeError("Nullifiers must be a tuple.")

        if not isinstance(self.ephemeral_public_keys, tuple):
            raise TypeError("Ephemeral public keys must be a tuple.")

        if not isinstance(self.note_ciphertexts, tuple):
            raise TypeError("Note ciphertexts must be a tuple.")

        # Transfer arity validation
        #
        # Paper references:
        # - Appendix A.3: defines N and M as the number of spent
        #   input notes and newly created output notes.
        # - Section 14.3: requires concrete deployment profiles
        #   to define which transfer arities are supported.
        #
        # IMPLEMENTATION CHOICE (Shielded Bitcoin v1):
        # The paper does not explicitly require N >= 1 or M >= 1.
        # Our profile requires at least one input and one output,
        # since transfer type 0x01 represents an ordinary shielded
        # transfer, not a peg-in or peg-out operation.
        #
        # No maximum arity is imposed at the data-model level yet.
        # The concrete proving system must later define which
        # arities can actually be verified.

        input_count = len(self.nullifiers)
        output_count = len(self.ephemeral_public_keys)

        if input_count == 0:
            raise ValueError(
                "A transfer envelope must contain at least one input."
            )

        if output_count == 0:
            raise ValueError(
                "A transfer envelope must contain at least one output."
            )

        if len(self.note_ciphertexts) != output_count:
            raise ValueError(
                "Ephemeral public keys and note ciphertexts "
                "must have the same length."
            )

        # Nullifier validation
        for nf in self.nullifiers:
            if not isinstance(nf, bytes):
                raise TypeError("Each nullifier must be bytes.")

            if len(nf) != 32:
                raise ValueError("Each nullifier must be 32 bytes.")

        # Ephemeral public key validation
        for pk in self.ephemeral_public_keys:
            if not isinstance(pk, bytes):
                raise TypeError("Each ephemeral public key must be bytes.")

            if len(pk) != 32:
                raise ValueError(
                    "Each ephemeral public key must be 32 bytes."
                )

        # Note ciphertext validation
        for ct in self.note_ciphertexts:
            if not isinstance(ct, bytes):
                raise TypeError("Each note ciphertext must be bytes.")

            if len(ct) != 67:
                raise ValueError(
                    "Each note ciphertext must be 67 bytes."
                )

        # Sender recovery ciphertext
        if not isinstance(self.recovery_ciphertext, bytes):
            raise TypeError("Recovery ciphertext must be bytes.")

        expected_recovery_length = 64 * output_count + 16

        if len(self.recovery_ciphertext) != expected_recovery_length:
            raise ValueError(
                "Invalid recovery ciphertext length."
            )

        # Proof
        if not isinstance(self.proof, bytes):
            raise TypeError("Proof must be bytes.")

        if len(self.proof) != 192:
            raise ValueError("Proof must be 192 bytes.")

    @property
    def input_count(self) -> int:
        return len(self.nullifiers)

    @property
    def output_count(self) -> int:
        return len(self.ephemeral_public_keys)
