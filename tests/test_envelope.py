
import pytest
from dataclasses import FrozenInstanceError
from models.header import HEADER
from models.envelope import Envelope
from dataclasses import replace

def make_valid_envelope():
    """Creates a structurally valid envelope for testing."""

    return Envelope(
        header=HEADER,
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
        replace(make_valid_envelope(), hanchor=-1)


def test_anchor_out_of_uint32_range_rejected():
    with pytest.raises(ValueError):
        replace(make_valid_envelope(), hanchor=2**32)  # 2^32


def test_boolean_anchor_rejected():
    with pytest.raises(TypeError):
        replace(make_valid_envelope(), hanchor=True)


def test_mismatched_output_vectors_rejected():
    with pytest.raises(ValueError):
        Envelope(
            header=HEADER,
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
            header=HEADER,
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
            header=HEADER,
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
            header=HEADER,
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
            header=HEADER,
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


# ---------------------------------------------------------
# Transfer arity validation
#
# Paper reference:
# - Section 14.3: the concrete deployment must define
#   the supported transfer arities.
#
# IMPLEMENTATION CHOICE (Shielded Bitcoin v1):
# N >= 1 and M >= 1.
# No maximum arity is imposed at the data-model level.
# ---------------------------------------------------------


@pytest.mark.parametrize(
    "input_count, output_count",
    [
        (1, 1),
        (1, 2),
        (2, 1),
        (2, 2),
        (3, 5),
        (5, 3),
    ],
)
def test_valid_transfer_arities(input_count, output_count):
    envelope = make_valid_envelope()

    nullifiers = tuple(
        bytes([i % 256]) * 32
        for i in range(input_count)
    )

    public_keys = tuple(
        bytes([i % 256]) * 32
        for i in range(output_count)
    )

    ciphertexts = tuple(
        bytes([i % 256]) * 67
        for i in range(output_count)
    )

    recovery_ciphertext = (
        b"\x01" * (64 * output_count + 16)
    )

    modified = replace(
        envelope,
        nullifiers=nullifiers,
        ephemeral_public_keys=public_keys,
        note_ciphertexts=ciphertexts,
        recovery_ciphertext=recovery_ciphertext,
    )

    assert modified.input_count == input_count
    assert modified.output_count == output_count


@pytest.mark.parametrize(
    "input_count, output_count",
    [
        (0, 0),
        (0, 1),
        (1, 0),
    ],
)
def test_invalid_transfer_arities(input_count, output_count):
    envelope = make_valid_envelope()

    nullifiers = tuple(
        b"\x01" * 32
        for _ in range(input_count)
    )

    public_keys = tuple(
        b"\x02" * 32
        for _ in range(output_count)
    )

    ciphertexts = tuple(
        b"\x03" * 67
        for _ in range(output_count)
    )

    recovery_ciphertext = (
        b"\x04" * (64 * output_count + 16)
    )

    with pytest.raises(ValueError):
        replace(
            envelope,
            nullifiers=nullifiers,
            ephemeral_public_keys=public_keys,
            note_ciphertexts=ciphertexts,
            recovery_ciphertext=recovery_ciphertext,
        )
