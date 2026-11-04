
from dataclasses import dataclass


@dataclass(frozen=True)
class Note:
    """
    Represents the private plaintext payload of a Shielded Bitcoin note.

    ptnote = (v, d, rseed)

    Paper references:
        - Section 5, pages 9-10: defines the note plaintext as ptnote = (v, d, rseed), including the meaning of each field.
        - Appendix A.2, page 42: specifies an 11-byte diversifier.

    Implementation checks:
        - v must be a non-negative integer, consistently with its unsigned satoshi representation.
        - d must be bytes of exactly 11 bytes.
        - rseed must be bytes; no fixed length is imposed because the cited specification does not define one.
    """

    v: int
    d: bytes
    rseed: bytes

    def __post_init__(self):
        # Validate note value
        if type(self.v) is not int:
            raise TypeError("Note value must be an integer.")

        if self.v < 0:
            raise ValueError("Note value cannot be negative.")

        # Validate diversifier
        if not isinstance(self.d, bytes):
            raise TypeError("Diversifier must be bytes.")

        if len(self.d) != 11:
            raise ValueError("Diversifier must be exactly 11 bytes.")

        # Validate note randomness
        if not isinstance(self.rseed, bytes):
            raise TypeError("Note randomness must be bytes.")
