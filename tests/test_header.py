
import pytest
from dataclasses import replace

from models.header import MAGIC, VERSION, TRANSFER_TYPE, HEADER
from models.envelope import Envelope
from serialization.encoder import encode_envelope
from serialization.decoder import decode_envelope


def make_valid_envelope():
    return Envelope(
        header=HEADER,
        hanchor=100,
        nullifiers=(b"\x01" * 32,),
        ephemeral_public_keys=(b"\x02" * 32,),
        note_ciphertexts=(b"\x03" * 67,),
        recovery_ciphertext=b"\x04" * 80,
        proof=b"\x05" * 192,
    )


# ---------------------------------------------------------
# 1. Header structure
# ---------------------------------------------------------

def test_header_fields():
    assert MAGIC == b"btc"
    assert VERSION == 1
    assert TRANSFER_TYPE == 0x01


def test_header_canonical_encoding():
    # Implementation-specific encoding choice:
    # The paper defines ("btc", 1, 0x01) and illustrates
    # a 6-byte header. We use a 2-byte little-endian
    # version field to preserve that total length.

    assert HEADER == b"btc\x01\x00\x01"
    assert len(HEADER) == 6


def test_header_version_little_endian():
    assert HEADER[3:5] == VERSION.to_bytes(2, "little")


def test_header_transfer_type():
    assert HEADER[5] == TRANSFER_TYPE


# ---------------------------------------------------------
# 2. Valid header acceptance
# ---------------------------------------------------------

def test_valid_header_accepted():
    envelope = make_valid_envelope()

    assert envelope.header == HEADER


# ---------------------------------------------------------
# 3. Invalid header rejection
# ---------------------------------------------------------

@pytest.mark.parametrize(
    "invalid_header",
    [
        b"abc\x01\x00\x01",  # Wrong magic
        b"btc\x02\x00\x01",  # Unsupported version 2
        b"btc\x00\x01\x01",  # Wrong version byte order
        b"btc\x01\x00\x02",  # Unsupported transfer type
        b"btc\x00\x00\x01",  # Unsupported version 0
        b"\x00" * 6,         # Empty/invalid discriminator
    ],
)
def test_invalid_header_rejected(invalid_header):
    envelope = make_valid_envelope()

    with pytest.raises(ValueError):
        replace(envelope, header=invalid_header) #we use replace instead of just changing the value of the header because dataclasses are frozen and we cannot change the value of the header directly, so with replace we create a new instance of the Envelope class with the new header value


@pytest.mark.parametrize(
    "invalid_header",
    [
        b"btc\x01\x01",        # 5 bytes
        b"btc\x01\x00\x01\x00", # 7 bytes
        b"",                   # Empty header
    ],
)
def test_invalid_header_length_rejected(invalid_header):
    envelope = make_valid_envelope()

    with pytest.raises(ValueError):
        replace(envelope, header=invalid_header)


@pytest.mark.parametrize(
    "invalid_header",
    [
        "btc",
        123,
        None,
        bytearray(b"btc\x01\x00\x01"),
    ],
)
def test_invalid_header_type_rejected(invalid_header):
    envelope = make_valid_envelope()

    with pytest.raises(TypeError):
        replace(envelope, header=invalid_header)


# ---------------------------------------------------------
# 4. Canonical serialization
# ---------------------------------------------------------

def test_serialized_envelope_starts_with_header():
    envelope = make_valid_envelope()

    encoded = encode_envelope(envelope)

    assert encoded[:6] == HEADER


def test_header_preserved_after_round_trip():
    envelope = make_valid_envelope()

    encoded = encode_envelope(envelope)
    decoded = decode_envelope(encoded)

    assert decoded.header == HEADER
    assert decoded == envelope


@pytest.mark.parametrize(
    "invalid_header",
    [
        b"abc\x01\x00\x01",
        b"btc\x02\x00\x01",
        b"btc\x01\x00\x02",
    ],
)
def test_decoder_rejects_invalid_header(invalid_header):
    envelope = make_valid_envelope()
    encoded = encode_envelope(envelope)

    # Replace only the first 6 bytes, preserving
    # the remaining canonical envelope encoding.
    malformed = invalid_header + encoded[6:]

    with pytest.raises(ValueError):
        decode_envelope(malformed)
