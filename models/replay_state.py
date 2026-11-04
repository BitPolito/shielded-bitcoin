
from dataclasses import dataclass

from models.leaf import Leaf
from models.envelope import Envelope


@dataclass(frozen=True) #even here remember that everytime is needed a change in the state, we will create a new instance of the ReplayState, so we can make it immutable
class ReplayState:
    """
    Represents the current Shielded Bitcoin replay state.

    S = (T, N, R, H)

    T: ordered note-tree leaves
    N: accepted nullifiers
    R: block-height to note-tree-root mapping
    H: ordered accepted envelopes
    
    Paper references:
        - Section 10, page 17: defines the replay state as S = (T, N, R, H).
        - Sections 9-10, pages 15-17: describe note-tree leaves, nullifiers, their acceptance, and their insertion into the replay state.
        - Section 10, page 17: defines the ordered accepted-envelope history and the block-level root map.
        - Appendix A.6, pages 44-45: defines the anchor window and the use of retained block-level roots.
        - Appendix A.7, page 45: specifies deterministic acceptance order and root storage after block replay.

    Implementation choices:
        - T is represented as a tuple of Leaf objects.
        - N is represented as a frozenset of byte strings.
        - R is represented as an ordered tuple of (height, root) pairs. 
        - H is represented as a tuple of Envelope objects.
        - Strictly increasing block heights, concrete Python types, non-empty roots, and immutability are implementation constraints.
        - This class validates the structure of the state, not the consistency of the complete replay transition.
    """

    note_tree: tuple[Leaf, ...] #note tree for the moment is an ordered tuple of leaves, but in the future it will be a Merkle tree
    nullifiers: frozenset[bytes]  #frozenset to avoid duplicates and to make it immutable
    block_roots: tuple[tuple[int, bytes], ...] #we want to keep the association r[hanchor] = ranchor, the couple must be inserted in growing order of anchor to keep determinism
    #again even here we haven't imposed yet a canonical binary length for the block roots, but we will do it in the future
    accepted_envelopes: tuple[Envelope, ...] #ordered history of accepted envelopes, we will keep it ordered by the order of acceptance, which is the order of insertion in the tuple

    def __post_init__(self):
        if not isinstance(self.note_tree, tuple):
            raise TypeError("Note tree must be a tuple.")

        for leaf in self.note_tree:
            if not isinstance(leaf, Leaf):
                raise TypeError("Note tree entries must be Leaf instances.")

        if not isinstance(self.nullifiers, frozenset):
            raise TypeError("Nullifiers must be a frozenset.")

        for nullifier in self.nullifiers:
            if not isinstance(nullifier, bytes):
                raise TypeError("Nullifiers must be bytes.")
            if len(nullifier) != 32:
                raise ValueError("Nullifiers must be exactly 32 bytes.")

        if not isinstance(self.block_roots, tuple):
            raise TypeError("Block roots must be a tuple.")

        previous_height = -1

        for entry in self.block_roots:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise TypeError(
                    "Each block root entry must be a (height, root) tuple."
                )

            height, root = entry

            if type(height) is not int:
                raise TypeError("Block height must be an integer.")

            if height < 0:
                raise ValueError("Block height cannot be negative.")

            if height <= previous_height:
                raise ValueError(
                    "Block roots must be ordered by strictly increasing height."
                )

            if not isinstance(root, bytes):
                raise TypeError("Block root must be bytes.")

            if not root:
                raise ValueError("Block root cannot be empty.")

            previous_height = height

        if not isinstance(self.accepted_envelopes, tuple):
            raise TypeError("Accepted envelopes must be a tuple.")

        for envelope in self.accepted_envelopes:
            if not isinstance(envelope, Envelope):
                raise TypeError(
                    "Accepted envelope entries must be Envelope instances."
                )
