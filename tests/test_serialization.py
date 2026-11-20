
import pytest

from serialization.encoder import encode_compact_size
from serialization.decoder import decode_compact_size
from serialization.encoder import encode_envelope
from serialization.decoder import decode_envelope
from models.envelope import Envelope
from models.header import HEADER

def make_valid_envelope():
    return Envelope(
        header=HEADER,
        hanchor=100,
        nullifiers=(b"n" * 32, b"m" * 32),
        ephemeral_public_keys=(b"p" * 32, b"q" * 32),
        note_ciphertexts=(b"c" * 67, b"d" * 67),
        recovery_ciphertext=b"r" * 144,
        proof=b"z" * 192,
    )


def test_envelope_round_trip():
    envelope = make_valid_envelope()

    encoded = encode_envelope(envelope)
    decoded = decode_envelope(encoded)

    assert decoded == envelope

def test_canonical_encoding_is_preserved_after_decoding():
    envelope = make_valid_envelope()
    encoded = encode_envelope(envelope)

    decoded = decode_envelope(encoded)

    assert encode_envelope(decoded) == encoded

def test_envelope_serialization_is_deterministic():
    envelope = make_valid_envelope()

    assert encode_envelope(envelope) == encode_envelope(envelope)


def test_decoder_rejects_non_canonical_output_count():
    envelope = make_valid_envelope()
    encoded = encode_envelope(envelope)

    # Header: 6 bytes
    # Anchor: 4 bytes
    # Input count: 1 byte
    # Output count: starts at offset 11
    malformed = encoded[:11] + b"\xfd\x02\x00" + encoded[12:]

    with pytest.raises(ValueError):
        decode_envelope(malformed)

def test_decoder_rejects_truncated_envelope():
    envelope = make_valid_envelope()
    encoded = encode_envelope(envelope)

    with pytest.raises(ValueError):
        decode_envelope(encoded[:-1])


def test_decoder_rejects_trailing_bytes():
    envelope = make_valid_envelope()
    encoded = encode_envelope(envelope)

    with pytest.raises(ValueError):
        decode_envelope(encoded + b"\x00")


def test_decoder_rejects_non_canonical_input_count():
    envelope = make_valid_envelope()
    encoded = encode_envelope(envelope)

    # Header: 6 bytes
    # Anchor: 4 bytes
    # Input count: starts at offset 10
    # Replace CompactSize(2) with non-minimal FD 02 00
    malformed = encoded[:10] + b"\xfd\x02\x00" + encoded[11:]

    with pytest.raises(ValueError):
        decode_envelope(malformed)


def test_decoder_rejects_non_bytes():
    with pytest.raises(TypeError):
        decode_envelope("not bytes")


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, b"\x00"),
        (252, b"\xfc"),
        (253, b"\xfd\xfd\x00"),
        (255, b"\xfd\xff\x00"),
        (256, b"\xfd\x00\x01"),
        (65535, b"\xfd\xff\xff"),
        (65536, b"\xfe\x00\x00\x01\x00"),
        (2**32, b"\xff\x00\x00\x00\x00\x01\x00\x00\x00"),
    ],
)
def test_encode_compact_size(value, expected):
    assert encode_compact_size(value) == expected


@pytest.mark.parametrize("value", [-1, 2**64])
def test_invalid_compact_size_range(value):
    with pytest.raises(ValueError):
        encode_compact_size(value)


@pytest.mark.parametrize("value", [True, False, 1.5, "253"])
def test_invalid_compact_size_type(value):
    with pytest.raises(TypeError):
        encode_compact_size(value)

@pytest.mark.parametrize("data", ["253", bytearray(b"\xfd\xfd\x00"), None])
def test_invalid_compact_size_input_type(data):
    with pytest.raises(TypeError):
        decode_compact_size(data)

@pytest.mark.parametrize(
    "encoded, expected",
    [
        (b"\x00", 0),
        (b"\xfc", 252),
        (b"\xfd\xfd\x00", 253),
        (b"\xfd\xff\x00", 255),
        (b"\xfd\x00\x01", 256),
        (b"\xfd\xff\xff", 65535),
        (b"\xfe\x00\x00\x01\x00", 65536),
        (b"\xff\x00\x00\x00\x00\x01\x00\x00\x00", 2**32),
    ],
)
def test_decode_compact_size(encoded, expected):
    value, next_offset = decode_compact_size(encoded)

    assert value == expected
    assert next_offset == len(encoded)


@pytest.mark.parametrize(
    "encoded",
    [
        b"\xfd\xfc\x00",
        b"\xfe\xff\xff\x00\x00",
        b"\xff\xff\xff\xff\xff\x00\x00\x00\x00",
    ],
)
def test_non_canonical_compact_size_rejected(encoded):
    with pytest.raises(ValueError):
        decode_compact_size(encoded)


@pytest.mark.parametrize(
    "encoded",
    [
        b"",
        b"\xfd",
        b"\xfd\xfd",
        b"\xfe\x00\x00\x01",
        b"\xff\x00\x00\x00\x00\x01\x00\x00",
    ],
)
def test_truncated_compact_size_rejected(encoded):
    with pytest.raises(ValueError):
        decode_compact_size(encoded)


def test_decode_compact_size_with_offset():
    data = b"\xaa\xfd\xfd\x00\xbb"

    value, next_offset = decode_compact_size(data, offset=1)

    assert value == 253
    assert next_offset == 4


# ---------------------------------------------------------
# CompactSize boundary and canonicality tests
#
# Paper reference:
# - Appendix A.5: vector counts must use canonical
#   Bitcoin-style CompactSize encoding.
#
# These tests verify the transition boundaries between
# the four CompactSize encoding formats.
# ---------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        (251, b"\xfb"),
        (254, b"\xfd\xfe\x00"),
        (65534, b"\xfd\xfe\xff"),
        (65537, b"\xfe\x01\x00\x01\x00"),
        (2**32 - 2, b"\xfe\xfe\xff\xff\xff"),
        (2**32 - 1, b"\xfe\xff\xff\xff\xff"),
        (2**32 + 1, b"\xff\x01\x00\x00\x00\x01\x00\x00\x00"),
        (2**64 - 1, b"\xff" + b"\xff" * 8),
    ],
)
def test_compact_size_additional_boundaries(value, expected):
    encoded = encode_compact_size(value)

    assert encoded == expected

    decoded, offset = decode_compact_size(encoded)

    assert decoded == value
    assert offset == len(encoded)


@pytest.mark.parametrize(
    "encoded",
    [
        b"\xfd\x00\x00",                  # 0 in 3 bytes
        b"\xfd\xfc\x00",                  # 252 in 3 bytes
        b"\xfe\xfd\x00\x00\x00",          # 253 in 5 bytes
        b"\xfe\xff\xff\x00\x00",          # 65535 in 5 bytes
        b"\xff\x00\x00\x01\x00\x00\x00\x00\x00",  # 65536 in 9 bytes
        b"\xff\xff\xff\xff\xff\x00\x00\x00\x00",  # 2^32-1 in 9 bytes
    ],
)
def test_compact_size_rejects_additional_non_minimal_encodings(encoded):
    with pytest.raises(ValueError):
        decode_compact_size(encoded)


@pytest.mark.parametrize(
    "value",
    [
        0,
        1,
        251,
        252,
        253,
        254,
        65534,
        65535,
        65536,
        65537,
        2**32 - 1,
        2**32,
        2**32 + 1,
        2**64 - 1,
    ],
)
def test_compact_size_round_trip_boundaries(value):
    encoded = encode_compact_size(value)

    decoded, offset = decode_compact_size(encoded)

    assert decoded == value
    assert offset == len(encoded)
    assert encode_compact_size(decoded) == encoded


def test_invalid_offset_rejected():
    with pytest.raises(ValueError):
        decode_compact_size(b"\x01", offset=2)

@pytest.mark.parametrize("offset", [True, 1.5, "1"])
def test_invalid_offset_type_rejected(offset):
    with pytest.raises(TypeError):
        decode_compact_size(b"\x01", offset)


# ---------------------------------------------------------
# Transfer arity decoding
#
# IMPLEMENTATION CHOICE (Shielded Bitcoin v1):
# Zero-input and zero-output transfers are rejected
# immediately after decoding the CompactSize counts.
# ---------------------------------------------------------


@pytest.mark.parametrize(
    "invalid_input_count, invalid_output_count",
    [
        (0, 2),
        (2, 0),
        (0, 0),
    ],
)
def test_decoder_rejects_zero_arities(
    invalid_input_count,
    invalid_output_count,
):
    envelope = make_valid_envelope()
    encoded = encode_envelope(envelope)

    # The header occupies bytes 0-5.
    # The anchor occupies bytes 6-9.
    # N and M are stored at offsets 10 and 11 because
    # the fixture uses counts below 253 (one byte each).

    malformed = (
        encoded[:10]
        + encode_compact_size(invalid_input_count)
        + encode_compact_size(invalid_output_count)
        + encoded[12:]
    )

    with pytest.raises(ValueError):
        decode_envelope(malformed)


@pytest.mark.parametrize(
    "input_count, output_count",
    [
        (1, 1),
        (1, 2),
        (2, 1),
        (3, 3),
        (3, 5),
        (5, 3),
    ],
)
def test_envelope_round_trip_variable_arities(
    input_count,
    output_count,
):
    from dataclasses import replace

    envelope = make_valid_envelope()

    modified = replace(
        envelope,
        nullifiers=tuple(
            bytes([i % 256]) * 32
            for i in range(input_count)
        ),
        ephemeral_public_keys=tuple(
            bytes([i % 256]) * 32
            for i in range(output_count)
        ),
        note_ciphertexts=tuple(
            bytes([i % 256]) * 67
            for i in range(output_count)
        ),
        recovery_ciphertext=(
            b"\x01" * (64 * output_count + 16)
        ),
    )

    encoded = encode_envelope(modified)
    decoded = decode_envelope(encoded)

    assert decoded == modified
    assert decoded.input_count == input_count
    assert decoded.output_count == output_count
    assert encode_envelope(decoded) == encoded


# ---------------------------------------------------------
# Malformed envelope parsing tests
#
# Paper reference:
# - Appendix A.5: the parser must reject truncated,
#   non-canonical and structurally inconsistent encodings.
#
# These tests verify that the decoder rejects malformed
# payloads before constructing an invalid Envelope.
# ---------------------------------------------------------


@pytest.mark.parametrize(
    "truncation_offset",
    [
        0,    # Empty payload
        1,    # Incomplete header
        5,    # Incomplete header
        6,    # Missing anchor
        9,    # Incomplete anchor
        10,   # Missing N and M
        11,   # Missing M
        12,   # Missing vectors
        20,   # Incomplete nullifier vector
        80,   # Incomplete ephemeral key vector
        150,  # Incomplete note ciphertext vector
        400,  # Incomplete recovery ciphertext
        609,  # Incomplete proof
    ],
)
def test_decoder_rejects_truncation_at_multiple_offsets(
    truncation_offset,
):
    envelope = make_valid_envelope()
    encoded = encode_envelope(envelope)

    # Every truncated prefix must be rejected.
    malformed = encoded[:truncation_offset]

    with pytest.raises(ValueError):
        decode_envelope(malformed)


@pytest.mark.parametrize(
    "declared_input_count, declared_output_count",
    [
        (3, 2),   # One additional input declared
        (2, 3),   # One additional output declared
        (5, 5),   # More inputs and outputs declared
        (10, 1),  # Excessive input count
        (1, 10),  # Excessive output count
    ],
)
def test_decoder_rejects_inconsistent_vector_counts(
    declared_input_count,
    declared_output_count,
):
    envelope = make_valid_envelope()
    encoded = encode_envelope(envelope)

    # The fixture uses N = 2 and M = 2.
    # Both counts occupy one byte at offsets 10 and 11.
    #
    # We modify the declared counts without adding the
    # corresponding vector elements.

    malformed = (
        encoded[:10]
        + encode_compact_size(declared_input_count)
        + encode_compact_size(declared_output_count)
        + encoded[12:]
    )

    with pytest.raises(ValueError):
        decode_envelope(malformed)


@pytest.mark.parametrize(
    "large_count",
    [
        253,
        65536,
        2**32,
        2**64 - 1,
    ],
)
@pytest.mark.parametrize(
    "count_field",
    ["input", "output"],
)
def test_decoder_rejects_oversized_declared_vectors(
    large_count,
    count_field,
):
    envelope = make_valid_envelope()
    encoded = encode_envelope(envelope)

    # Canonically encode an extremely large count,
    # while leaving the actual payload unchanged.
    #
    # The decoder must reject the inconsistency
    # without attempting to allocate such vectors.

    if count_field == "input":
        malformed = (
            encoded[:10]
            + encode_compact_size(large_count)
            + encode_compact_size(2)
            + encoded[12:]
        )
    else:
        malformed = (
            encoded[:10]
            + encode_compact_size(2)
            + encode_compact_size(large_count)
            + encoded[12:]
        )

    with pytest.raises(ValueError):
        decode_envelope(malformed)

