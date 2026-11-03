
import pytest
from dataclasses import FrozenInstanceError

from models.envelope import Envelope


def make_valid_envelope():
    """Creates a structurally valid envelope for testing."""

    return Envelope(
        header=b"\x00" * 6,
        hanchor=100,
        nullifiers=(b"\x01" * 32, b"\x02" * 32),
        ephemeral_public_keys=(b"\x03" * 32, b"\x04" * 32),
        note_ciphertexts=(b"\x05" * 67, b"\x06" * 67),
        recovery_ciphertext=b"\x07" * 144,
        proof=b"\x08" * 192
    )


def test_valid_envelope():
    envelope = make_valid_envelope()

    assert envelope.input_count == 2
    assert envelope.output_count == 2


def test_negative_anchor_rejected():
    with pytest.raises(ValueError):
        Envelope(
            header=b"\x00" * 6,
            hanchor=-1,
            nullifiers=(),
            ephemeral_public_keys=(),
            note_ciphertexts=(),
            recovery_ciphertext=b"\x00" * 16,
            proof=b"\x00" * 192
        )


def test_anchor_out_of_uint32_range_rejected():
    with pytest.raises(ValueError):
        Envelope(
            header=b"\x00" * 6,
            hanchor=2**32,
            nullifiers=(),
            ephemeral_public_keys=(),
            note_ciphertexts=(),
            recovery_ciphertext=b"\x00" * 16,
            proof=b"\x00" * 192
        )


def test_boolean_anchor_rejected():
    with pytest.raises(TypeError):
        Envelope(
            header=b"\x00" * 6,
            hanchor=True,
            nullifiers=(),
            ephemeral_public_keys=(),
            note_ciphertexts=(),
            recovery_ciphertext=b"\x00" * 16,
            proof=b"\x00" * 192
        )


def test_mismatched_output_vectors_rejected():
    with pytest.raises(ValueError):
        Envelope(
            header=b"\x00" * 6,
            hanchor=100,
            nullifiers=(),
            ephemeral_public_keys=(b"\x01" * 32,),
            note_ciphertexts=(),
            recovery_ciphertext=b"\x00" * 80,
            proof=b"\x00" * 192
        )


def test_invalid_nullifier_length_rejected():
    with pytest.raises(ValueError):
        Envelope(
            header=b"\x00" * 6,
            hanchor=100,
            nullifiers=(b"\x01" * 31,),
            ephemeral_public_keys=(),
            note_ciphertexts=(),
            recovery_ciphertext=b"\x00" * 16,
            proof=b"\x00" * 192
        )


def test_invalid_note_ciphertext_length_rejected():
    with pytest.raises(ValueError):
        Envelope(
            header=b"\x00" * 6,
            hanchor=100,
            nullifiers=(),
            ephemeral_public_keys=(b"\x01" * 32,),
            note_ciphertexts=(b"\x02" * 66,),
            recovery_ciphertext=b"\x00" * 80,
            proof=b"\x00" * 192
        )


def test_invalid_recovery_ciphertext_length_rejected():
    with pytest.raises(ValueError):
        Envelope(
            header=b"\x00" * 6,
            hanchor=100,
            nullifiers=(),
            ephemeral_public_keys=(b"\x01" * 32,),
            note_ciphertexts=(b"\x02" * 67,),
            recovery_ciphertext=b"\x00" * 79,
            proof=b"\x00" * 192
        )


def test_invalid_proof_length_rejected():
    with pytest.raises(ValueError):
        Envelope(
            header=b"\x00" * 6,
            hanchor=100,
            nullifiers=(),
            ephemeral_public_keys=(),
            note_ciphertexts=(),
            recovery_ciphertext=b"\x00" * 16,
            proof=b"\x00" * 191
        )


def test_envelope_is_immutable():
    envelope = make_valid_envelope()

    with pytest.raises(FrozenInstanceError):
        envelope.hanchor = 200
