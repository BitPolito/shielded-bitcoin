
from dataclasses import dataclass

@dataclass(frozen=True)
class Envelope:
    """
    Represents a Shielded Bitcoin transfer envelope.

    e = (Body(e), proof(e))
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

        # Consistent vector lengths
        output_count = len(self.ephemeral_public_keys)

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
