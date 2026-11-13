
import pytest

from serialization.encoder import encode_compact_size
from serialization.decoder import decode_compact_size
from serialization.encoder import encode_envelope
from serialization.decoder import decode_envelope
from models.envelope import Envelope

def make_valid_envelope():
    return Envelope(
        header=b"h" * 6,
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


def test_invalid_offset_rejected():
    with pytest.raises(ValueError):
        decode_compact_size(b"\x01", offset=2)

@pytest.mark.parametrize("offset", [True, 1.5, "1"])
def test_invalid_offset_type_rejected(offset):
    with pytest.raises(TypeError):
        decode_compact_size(b"\x01", offset)