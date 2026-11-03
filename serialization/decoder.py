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

def decode_compact_size(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Decode a canonical Bitcoin CompactSize integer.

    Returns:
        (decoded_value, next_offset)
    """

    if not isinstance(data, bytes):
        raise TypeError("Input data must be bytes.")

    if type(offset) is not int:
        raise TypeError("Offset must be an integer.")

    if not 0 <= offset <= len(data):
        raise ValueError("Offset out of range.")

    if offset == len(data):
        raise ValueError("Insufficient data for CompactSize.")

    prefix = data[offset]
    offset += 1

    # Direct encoding: 0 to 252
    if prefix <= 252:
        return prefix, offset

    # Determine payload size
    if prefix == 0xfd:
        size = 2
        minimum = 253

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
