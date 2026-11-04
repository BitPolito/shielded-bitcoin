
from dataclasses import dataclass


@dataclass(frozen=True)
class Leaf:
    """
    Represents a leaf value in the note Merkle tree.

    The leaf hash is derived from public output data according
    to the H_leaf construction defined by the protocol.

    Its global tree position is assigned by the replay process
    and is therefore not part of this object.
    
    Paper references:
        - Section 5, pages 9-10: states that note-tree leaves are derived by replay from public output data.
        - Section 9, page 15: defines the leaf derivation formula: ell_j = H_leaf(const_salt, hbody, j, pk_eph,j, ct_note,j, haux,j).
        - Section 9, page 15: distinguishes the output index j from the global Merkle-tree position.
        - Section 10, pages 16-17: specifies that replay assigns canonical positions when accepted leaves are appended.

    Implementation choices:
        - The class stores only the resulting leaf hash.
        - The global position and derivation inputs are deliberately kept outside this model.
        - The byte representation and non-empty constraint are implementation choices; no fixed hash output length is imposed here.
        - Immutability is an implementation design choice.
    """

    leaf_hash: bytes

    def __post_init__(self):
        if not isinstance(self.leaf_hash, bytes):
            raise TypeError("Leaf hash must be bytes.")

        if not self.leaf_hash:
            raise ValueError("Leaf hash cannot be empty.")
