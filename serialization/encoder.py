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


def encode_compact_size(n: int) -> bytes:
    """
    Encode a non-negative integer using Bitcoin CompactSize.
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
