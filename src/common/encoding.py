"""
encoding.py — Endianness-explicit encoding helpers.

Policy: BIG-ENDIAN is the canonical representation throughout this project.
The 64-bit length field in Merkle-Damgård strengthening is big-endian (per SHA-1/MD5 style).
"""

import struct


def encode_uint64_be(n: int) -> bytes:
    """Encode a 64-bit unsigned integer in big-endian (8 bytes)."""
    if not (0 <= n < 2**64):
        raise ValueError(f"Value {n} out of range for uint64")
    return struct.pack(">Q", n)


def decode_uint64_be(b: bytes) -> int:
    """Decode a big-endian 64-bit unsigned integer from 8 bytes."""
    if len(b) != 8:
        raise ValueError("decode_uint64_be requires exactly 8 bytes")
    return struct.unpack(">Q", b)[0]


def encode_uint32_be(n: int) -> bytes:
    """Encode a 32-bit unsigned integer in big-endian (4 bytes)."""
    if not (0 <= n < 2**32):
        raise ValueError(f"Value {n} out of range for uint32")
    return struct.pack(">I", n)


def decode_uint32_be(b: bytes) -> int:
    """Decode a big-endian 32-bit unsigned integer from 4 bytes."""
    if len(b) != 4:
        raise ValueError("decode_uint32_be requires exactly 4 bytes")
    return struct.unpack(">I", b)[0]


def zero_pad_left(b: bytes, target_len: int) -> bytes:
    """Left-pad bytes with zeros to reach target_len. Raises if already longer."""
    if len(b) > target_len:
        raise ValueError(
            f"zero_pad_left: input length {len(b)} exceeds target {target_len}"
        )
    return b.rjust(target_len, b"\x00")


def zero_pad_right(b: bytes, target_len: int) -> bytes:
    """Right-pad bytes with zeros to reach target_len. Raises if already longer."""
    if len(b) > target_len:
        raise ValueError(
            f"zero_pad_right: input length {len(b)} exceeds target {target_len}"
        )
    return b.ljust(target_len, b"\x00")


def encode_group_element(x: int, byte_len: int) -> bytes:
    """Serialize a group element (integer mod p) to *byte_len* big-endian bytes."""
    return x.to_bytes(byte_len, "big")


def decode_group_element(b: bytes) -> int:
    """Deserialize a big-endian byte string back to an integer."""
    return int.from_bytes(b, "big")


def pack_tuple(*items: bytes) -> bytes:
    """Pack multiple variable-length byte strings with length prefixes (big-endian 4-byte)."""
    parts = []
    for item in items:
        parts.append(struct.pack(">I", len(item)))
        parts.append(item)
    return b"".join(parts)


def unpack_tuple(data: bytes, count: int) -> list[bytes]:
    """Unpack a tuple packed by pack_tuple."""
    items = []
    offset = 0
    for _ in range(count):
        if offset + 4 > len(data):
            raise ValueError("unpack_tuple: data too short for length prefix")
        (length,) = struct.unpack_from(">I", data, offset)
        offset += 4
        if offset + length > len(data):
            raise ValueError("unpack_tuple: data too short for item")
        items.append(data[offset : offset + length])
        offset += length
    return items
