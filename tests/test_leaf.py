
import pytest
from dataclasses import FrozenInstanceError

from models.leaf import Leaf


def make_valid_leaf(**overrides):
    data = {
        "leaf_hash": b"leaf-hash-value",
    }
    data.update(overrides)
    return Leaf(**data)


def test_valid_leaf():
    leaf = make_valid_leaf()

    assert leaf.leaf_hash == b"leaf-hash-value"


def test_leaf_hash_must_be_bytes():
    with pytest.raises(TypeError):
        make_valid_leaf(leaf_hash="not bytes")


def test_leaf_hash_cannot_be_empty():
    with pytest.raises(ValueError):
        make_valid_leaf(leaf_hash=b"")


def test_leaf_is_immutable():
    leaf = make_valid_leaf()

    with pytest.raises(FrozenInstanceError):
        leaf.leaf_hash = b"another-hash"


def test_leaf_has_no_position():
    leaf = make_valid_leaf()

    assert not hasattr(leaf, "position")


def test_leaf_has_no_output_index():
    leaf = make_valid_leaf()

    assert not hasattr(leaf, "output_index")

