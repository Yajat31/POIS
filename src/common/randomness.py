"""
randomness.py — OS-randomness wrappers.

Only os.urandom is used — no external crypto libraries.
Provides uniform sampling helpers used throughout.
"""

import os


def random_bytes(n: int) -> bytes:
    """Return *n* cryptographically random bytes (from OS)."""
    if n <= 0:
        raise ValueError("random_bytes: n must be positive")
    return os.urandom(n)


def random_int(low: int, high: int) -> int:
    """Return a uniformly random integer in [low, high] inclusive.

    Uses rejection sampling over random_bytes to ensure uniformity.
    """
    if low > high:
        raise ValueError("random_int: low must be <= high")
    span = high - low + 1
    bit_len = span.bit_length()
    byte_len = (bit_len + 7) // 8
    mask = (1 << bit_len) - 1
    while True:
        raw = int.from_bytes(os.urandom(byte_len), "big") & mask
        if raw < span:
            return low + raw


def random_int_range(n: int) -> int:
    """Return a uniformly random integer in [0, n-1]."""
    return random_int(0, n - 1)


def random_nonzero_bytes(n: int) -> bytes:
    """Return *n* random bytes with each byte guaranteed nonzero (for PKCS#1 v1.5 padding)."""
    result = bytearray()
    while len(result) < n:
        chunk = os.urandom(n - len(result))
        for b in chunk:
            if b != 0:
                result.append(b)
    return bytes(result)


def random_odd_int(bits: int) -> int:
    """Return a random *bits*-bit odd integer with the high bit set."""
    byte_len = (bits + 7) // 8
    raw = bytearray(os.urandom(byte_len))
    # Set the high bit
    raw[0] |= 1 << ((bits - 1) % 8)
    # Ensure the result is exactly *bits* bits by masking
    raw[0] &= (1 << (bits % 8 or 8)) - 1
    raw[0] |= 1 << ((bits - 1) % 8)
    # Set low bit (make odd)
    raw[-1] |= 1
    n = int.from_bytes(raw, "big")
    # Force bit-length if byte boundary caused an issue
    n |= 1 << (bits - 1)
    n |= 1  # odd
    return n


def random_element_zp(p: int) -> int:
    """Return a uniformly random element of Z_p (i.e. in [1, p-1])."""
    return random_int(1, p - 1)


def random_element_zq(q: int) -> int:
    """Return a uniformly random element of Z_q (i.e. in [1, q-1])."""
    return random_int(1, q - 1)
