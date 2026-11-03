
import pytest

from serialization.encoder import encode_compact_size
from serialization.decoder import decode_compact_size


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