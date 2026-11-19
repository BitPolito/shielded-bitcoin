
import pytest
from dataclasses import FrozenInstanceError

from models.leaf import Leaf
from models.envelope import Envelope
from models.replay_state import ReplayState
from models.header import HEADER

def make_valid_envelope():
    return Envelope(
        header=HEADER,
        hanchor=100,
        nullifiers=(b"n" * 32,),
        ephemeral_public_keys=(b"k" * 32,),
        note_ciphertexts=(b"c" * 67,),
        recovery_ciphertext=b"r" * 80,
        proof=b"p" * 192,
    )


def make_valid_state(**overrides):
    data = {
        "note_tree": (),
        "nullifiers": frozenset(),
        "block_roots": (),
        "accepted_envelopes": (),
    }
    data.update(overrides)
    return ReplayState(**data)


def test_empty_replay_state():
    state = make_valid_state()

    assert state.note_tree == ()
    assert state.nullifiers == frozenset()
    assert state.block_roots == ()
    assert state.accepted_envelopes == ()


def test_valid_replay_state():
    leaf = Leaf(leaf_hash=b"leaf")
    envelope = make_valid_envelope()

    state = make_valid_state(
        note_tree=(leaf,),
        nullifiers=frozenset({b"n" * 32}),
        block_roots=((100, b"root"),),
        accepted_envelopes=(envelope,),
    )

    assert state.note_tree == (leaf,)
    assert b"n" * 32 in state.nullifiers
    assert state.block_roots == ((100, b"root"),)
    assert state.accepted_envelopes == (envelope,)


def test_note_tree_must_be_tuple():
    with pytest.raises(TypeError):
        make_valid_state(note_tree=[])


def test_note_tree_entries_must_be_leaves():
    with pytest.raises(TypeError):
        make_valid_state(note_tree=(b"not a leaf",))


def test_nullifiers_must_be_frozenset():
    with pytest.raises(TypeError):
        make_valid_state(nullifiers=set())


def test_nullifiers_must_be_bytes():
    with pytest.raises(TypeError):
        make_valid_state(nullifiers=frozenset({"invalid"}))


def test_nullifiers_must_have_32_bytes():
    with pytest.raises(ValueError):
        make_valid_state(nullifiers=frozenset({b"short"}))


def test_block_roots_must_be_tuple():
    with pytest.raises(TypeError):
        make_valid_state(block_roots=[])


def test_block_root_entry_must_be_pair():
    with pytest.raises(TypeError):
        make_valid_state(block_roots=((100,),))


def test_block_height_must_be_integer():
    with pytest.raises(TypeError):
        make_valid_state(block_roots=((True, b"root"),))


def test_block_height_cannot_be_negative():
    with pytest.raises(ValueError):
        make_valid_state(block_roots=((-1, b"root"),))


def test_block_roots_must_be_strictly_ordered():
    with pytest.raises(ValueError):
        make_valid_state(
            block_roots=((101, b"root1"), (100, b"root2"))
        )


def test_block_heights_must_be_unique():
    with pytest.raises(ValueError):
        make_valid_state(
            block_roots=((100, b"root1"), (100, b"root2"))
        )


def test_block_root_must_be_bytes():
    with pytest.raises(TypeError):
        make_valid_state(block_roots=((100, "root"),))


def test_block_root_cannot_be_empty():
    with pytest.raises(ValueError):
        make_valid_state(block_roots=((100, b""),))


def test_accepted_envelopes_must_be_tuple():
    with pytest.raises(TypeError):
        make_valid_state(accepted_envelopes=[])


def test_accepted_envelopes_must_contain_envelopes():
    with pytest.raises(TypeError):
        make_valid_state(accepted_envelopes=(b"not an envelope",))


def test_replay_state_is_immutable():
    state = make_valid_state()

    with pytest.raises(FrozenInstanceError):
        state.nullifiers = frozenset({b"n" * 32})
