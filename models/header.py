"""
Shielded Bitcoin canonical transfer header.

Paper references:
- Section 3: defines the logical header as ("btc", 1, 0x01).
- Section 11: explains the role of magic, version and transfer type.
- Appendix A.4: uses a 6-byte header in the illustrative
  serialized envelope.

IMPLEMENTATION CHOICE:
The paper specifies the logical header components and uses
a total header length of 6 bytes, but does not explicitly
assign a binary width to each component.

A direct encoding with a 3-byte magic, a 1-byte version
and a 1-byte transfer type would occupy only 5 bytes.

We therefore allocate the additional byte to the version
field, representing it as an unsigned 16-bit little-endian
integer instead of an unsigned 8-bit integer.

This preserves the 6-byte header size while increasing
the available version namespace from 256 to 65536 values.

This encoding is specific to our implementation profile
and is not explicitly prescribed by the paper.
"""

MAGIC = b"btc"
VERSION = 1
TRANSFER_TYPE = 0x01

HEADER = (
    MAGIC
    + VERSION.to_bytes(2, byteorder="little")
    + TRANSFER_TYPE.to_bytes(1, byteorder="little")
)