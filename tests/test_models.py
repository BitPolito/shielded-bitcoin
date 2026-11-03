
import pytest

from models.note import Note


def test_valid_note():
    note = Note(
        v=10000,
        d=b"12345678901",
        rseed=b"example_randomness"
    )

    assert note.v == 10000
    assert note.d == b"12345678901"
    assert note.rseed == b"example_randomness"


def test_negative_value():
    with pytest.raises(ValueError):
        Note(v=-1, d=b"12345678901", rseed=b"randomness")


def test_boolean_value():
    with pytest.raises(TypeError):
        Note(v=True, d=b"12345678901", rseed=b"randomness")


def test_invalid_diversifier_length():
    with pytest.raises(ValueError):
        Note(v=100, d=b"123", rseed=b"randomness")


def test_invalid_diversifier_type():
    with pytest.raises(TypeError):
        Note(v=100, d="12345678901", rseed=b"randomness")


def test_invalid_rseed_type():
    with pytest.raises(TypeError):
        Note(v=100, d=b"12345678901", rseed="randomness")


def test_note_is_immutable():
    note = Note(v=100, d=b"12345678901", rseed=b"randomness")

    with pytest.raises(AttributeError):
        note.v = 200
