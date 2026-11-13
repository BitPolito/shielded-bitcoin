#Rules:
#Field  	                Encoding
#header	                    6 byte
#hanchor	                uint32 little-endian
#N, M	                    Canonical Bitcoin CompactSize
#Nullifier	                32 byte each
#Ephimeral public key	    32 byte each
#Note ciphertext	        67 byte each
#Recovery ciphertext	    Length determined by format
#Proof	                    192 byte, after the body

#These values can be found in the paper at the end of the page 43.

from models.envelope import Envelope

def decode_envelope(data: bytes) -> Envelope:
    """
    Decodes a canonical serialized Envelope.

    Rejects truncated data, invalid vector lengths,
    non-canonical CompactSize values, and trailing bytes.
    """

    if not isinstance(data, bytes):
        raise TypeError("Serialized envelope must be bytes.")

    offset = 0

    def read_exact(size: int) -> bytes:
        nonlocal offset #nonlocal allows the inner function to modify the offset variable from the enclosing scope. This is necessary because we want to keep track of how many bytes we've read from the data as we decode the envelope.

        if len(data) - offset < size:
            raise ValueError("Serialized envelope is truncated.")

        result = data[offset:offset + size]
        offset += size
        return result

    # Fixed-width fields
    header = read_exact(6)
    hanchor = int.from_bytes(
        read_exact(4),
        byteorder="little"
    )

    # Vector counts
    input_count, offset = decode_compact_size(data, offset) #here we pass the envelope data and the current offset to the decode_compact_size function, which returns the decoded input_count and the updated offset.
    output_count, offset = decode_compact_size(data, offset)

    # Check that enough bytes remain for the nullifiers
    if input_count > (len(data) - offset) // 32: #here we check if the number of input nullifiers specified by input_count can fit in the remaining bytes of data. Each nullifier is 32 bytes, so we divide the remaining length of data by 32 to see how many nullifiers can fit. If input_count exceeds this number, it means there are not enough bytes left to read all the nullifiers, and we raise a ValueError.
        raise ValueError("Invalid nullifier vector length.")

    nullifiers = tuple(
        read_exact(32)
        for _ in range(input_count)
    )

    # Check that enough bytes remain for the public keys
    if output_count > (len(data) - offset) // 32:
        raise ValueError("Invalid ephemeral public key vector length.")

    ephemeral_public_keys = tuple(
        read_exact(32)
        for _ in range(output_count)
    )

    # Check that enough bytes remain for the note ciphertexts
    if output_count > (len(data) - offset) // 67:
        raise ValueError("Invalid note ciphertext vector length.")

    note_ciphertexts = tuple(
        read_exact(67)
        for _ in range(output_count)
    )

    # Sender-recovery ciphertext:
    # 64 bytes per output plus one 16-byte authentication tag
    recovery_length = 64 * output_count + 16
    recovery_ciphertext = read_exact(recovery_length)

    # Proof
    proof = read_exact(192)

    # No trailing data is allowed
    if offset != len(data):
        raise ValueError("Serialized envelope contains trailing bytes.")

    return Envelope(
        header=header,
        hanchor=hanchor,
        nullifiers=nullifiers,
        ephemeral_public_keys=ephemeral_public_keys,
        note_ciphertexts=note_ciphertexts,
        recovery_ciphertext=recovery_ciphertext,
        proof=proof,
    )


"""
Paper references:
- Appendix A.3, page 43: defines the logical envelope
  fields and their order.
- Appendix A.5, page 44: requires canonical decoding and
  rejection of truncated, longer, non-minimal, reordered,
  undecodable, or otherwise non-canonical encodings.

Implementation choices:
- The decoder uses the concrete field widths enforced by
  the current Envelope model.
- It rejects trailing bytes and checks vector sizes before
  iterating over their elements.
"""


def decode_compact_size(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Decode a canonical Bitcoin CompactSize integer.

    Returns:
        (decoded_value, next_offset)

    Paper reference:
        - Appendix A.5, page 44: requires canonical parsing and rejection of non-minimal, shorter, longer, undecodable, or otherwise non-canonical encodings.

    Implementation:
        - Checks CompactSize prefixes, available bytes, integer bounds, and minimal representation.
        - Offset validation and Python type checks are additional implementation safeguards.
    """

    if not isinstance(data, bytes):
        raise TypeError("Input data must be bytes.")

    if type(offset) is not int:
        raise TypeError("Offset must be an integer.")

    if not 0 <= offset <= len(data):
        raise ValueError("Offset out of range.")

    if offset == len(data):
        raise ValueError("Insufficient data for CompactSize.")

    prefix = data[offset] # Read the first byte
    offset += 1

    # Direct encoding: 0 to 252
    if prefix <= 252:
        return prefix, offset #if prefix is 0-252, the value is the prefix itself, and we return the next offset

    # Determine payload size
    if prefix == 0xfd:
        size = 2 #2 bytes
        minimum = 253 #useful for checking in the last part

    elif prefix == 0xfe:
        size = 4
        minimum = 0x10000

    else:
        size = 8
        minimum = 0x100000000

    # Check available bytes
    if len(data) - offset < size:
        raise ValueError("Truncated CompactSize encoding.")

    # Decode little-endian integer
    value = int.from_bytes(
        data[offset:offset + size],
        byteorder="little"
    )

    # Canonical encoding check
    if value < minimum:
        raise ValueError("Non-canonical CompactSize encoding.")

    return value, offset + size
