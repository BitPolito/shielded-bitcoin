#Rules:
#Field  	                Encoding
#header	                    6 byte
#hanchor	                uint32 little-endian
#N, M	                    Canonical Bitcoin CompactSize
#Nullifier	                32 byte each
#Ephimeral public key	32 byte each
#Note ciphertext	        67 byte each
#Recovery ciphertext	    Length determined by format
#Proof	                    192 byte, after the body

#These values can be found in the paper at the end of the page 43.

from models.envelope import Envelope

def encode_envelope(envelope: Envelope) -> bytes:
    """
    Serializes an Envelope using the canonical field order
    defined in Appendix A.3 and A.5.
    """

    if not isinstance(envelope, Envelope):
        raise TypeError("Expected an Envelope instance.")

    encoded = bytearray() #here we create a bytearray to hold the serialized data. A bytearray represents a mutable sequence of bytes, which is useful for building up the serialized representation of the Envelope.

    # Fixed-width fields
    encoded.extend(envelope.header)  #the function extend is used to append the bytes of the header to the encoded bytearray. The header is expected to be a 6-byte field, as specified in the serialization rules.
    encoded.extend(envelope.hanchor.to_bytes(4, byteorder="little")) #from the hanchor we convert the integer value to a 4-byte little-endian and then we append it to the encoded bytearray.

    #while in decoder we decided as soon as possible to check if input and ouptu count are valid (at the moment this means that both must be major than 0), here we do not check this because we assume that the envelope has already been validated before being passed to the encoder. This is a design choice that assumes that the encoder will only be used with valid Envelope instances, and that any necessary validation has already been performed before calling this function.
    # Vector counts
    encoded.extend(encode_compact_size(envelope.input_count)) #we append input and output counts using the function defined below, to encode in BTC CompactSize
    encoded.extend(encode_compact_size(envelope.output_count))

    # Input nullifiers
    for nullifier in envelope.nullifiers:
        encoded.extend(nullifier)

    # Output ephemeral public keys
    for public_key in envelope.ephemeral_public_keys:
        encoded.extend(public_key)

    # Output note ciphertexts
    for ciphertext in envelope.note_ciphertexts:
        encoded.extend(ciphertext)

    # Sender-recovery ciphertext
    encoded.extend(envelope.recovery_ciphertext)

    # Proof is serialized after the body
    encoded.extend(envelope.proof)

    return bytes(encoded)


"""
Paper references:
- Appendix A.3, page 43: defines the logical envelope body
  and the order of its fields.
- Appendix A.5, page 44: defines canonical serialization,
  fixed-width little-endian integers, CompactSize vector
  counts, and increasing vector index order. It also specifies
  that the proof is serialized after body_bytes(e).

Implementation choices:
- This encoder uses the concrete field widths enforced by
  the current Envelope model.
"""


def encode_compact_size(n: int) -> bytes:
    """
    Encode a non-negative integer using Bitcoin CompactSize.

    Paper reference:
        - Appendix A.5, page 44: specifies Bitcoin-style canonical CompactSize encoding for vector counts.

    Implementation:
        - Implements the CompactSize integer encoding and rejects values outside the unsigned 64-bit range.
    """

    if type(n) is not int:
        raise TypeError("CompactSize value must be an integer.")

    if not 0 <= n <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("CompactSize value out of range.")

    if n <= 252:
        return n.to_bytes(1, byteorder="little")

    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, byteorder="little")

    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, byteorder="little")

    return b"\xff" + n.to_bytes(8, byteorder="little")
