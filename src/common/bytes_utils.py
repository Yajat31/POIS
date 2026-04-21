"""
bytes_utils.py — Canonical byte/int/bit conversion helpers.

Endianness policy: BIG-ENDIAN throughout (big-endian is the mathematical
convention and is required by MD-strengthening's 64-bit length field).
All conversions here are consistent with that policy.
"""


def int_to_bytes(n: int, length: int | None = None) -> bytes:
    """Convert non-negative integer to big-endian bytes.
    If *length* is given, the result is zero-padded (or truncated) to that length.
    """
    if n < 0:
        raise ValueError("int_to_bytes requires a non-negative integer")
    byte_length = (n.bit_length() + 7) // 8 or 1
    raw = n.to_bytes(byte_length, "big")
    if length is None:
        return raw
    if len(raw) > length:
        raise ValueError(
            f"Integer {n} requires {len(raw)} bytes but length={length} was given"
        )
    return raw.rjust(length, b"\x00")


def bytes_to_int(b: bytes) -> int:
    """Convert big-endian bytes to a non-negative integer."""
    return int.from_bytes(b, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    if len(a) != len(b):
        raise ValueError(f"xor_bytes: length mismatch {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


def xor_bytes_unequal(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings; truncate to the shorter length."""
    length = min(len(a), len(b))
    return bytes(a[i] ^ b[i] for i in range(length))


def bytes_to_bits(b: bytes) -> list[int]:
    """Convert bytes to a list of bits (MSB first within each byte)."""
    bits = []
    for byte in b:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    """Convert a list of bits (MSB first) to bytes, padding with 0s on the right."""
    # Pad to multiple of 8
    padded = bits + [0] * ((-len(bits)) % 8)
    result = bytearray()
    for i in range(0, len(padded), 8):
        byte = 0
        for bit in padded[i : i + 8]:
            byte = (byte << 1) | bit
        result.append(byte)
    return bytes(result)


def bits_to_int(bits: list[int]) -> int:
    """Convert MSB-first bit list to integer."""
    n = 0
    for b in bits:
        n = (n << 1) | b
    return n


def int_to_bits(n: int, length: int) -> list[int]:
    """Convert integer to MSB-first bit list of exactly *length* bits."""
    bits = []
    for i in range(length - 1, -1, -1):
        bits.append((n >> i) & 1)
    return bits


def hex_to_bytes(h: str) -> bytes:
    """Convert hex string (with or without 0x prefix) to bytes."""
    h = h.strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    if len(h) % 2:
        h = "0" + h
    return bytes.fromhex(h)


def bytes_to_hex(b: bytes) -> str:
    """Convert bytes to lowercase hex string."""
    return b.hex()


def split_half(b: bytes) -> tuple[bytes, bytes]:
    """Split bytes exactly in half; raises if odd length."""
    if len(b) % 2 != 0:
        raise ValueError("split_half requires even-length bytes")
    mid = len(b) // 2
    return b[:mid], b[mid:]


def fixed_xor(a: bytes, b: bytes, block_size: int) -> bytes:
    """XOR two blocks, each exactly block_size bytes."""
    if len(a) != block_size or len(b) != block_size:
        raise ValueError("fixed_xor: both inputs must be exactly block_size bytes")
    return xor_bytes(a, b)
