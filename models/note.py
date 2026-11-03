
from dataclasses import dataclass


@dataclass(frozen=True)
class Note:
    """
    Represents the private plaintext payload of a Shielded Bitcoin note.

    ptnote = (v, d, rseed)
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
