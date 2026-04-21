"""
padding.py — Padding utilities.

Implements:
  1. Merkle-Damgård strengthening padding (for PA#7):
     append 1-bit, enough 0-bits, 64-bit big-endian message-length field.
  2. PKCS#1 v1.5 padding (for PA#12 RSA encryption/decryption).
  3. Block padding (ISO/IEC 7816 style) for CBC-MAC (PA#5).
"""

import struct


# ─────────────────────────────────────────────────────────────
#  Merkle-Damgård Strengthening Padding (PA#7)
# ─────────────────────────────────────────────────────────────

def md_pad(message: bytes, block_size: int) -> bytes:
    """Apply Merkle-Damgård strengthening padding.

    Appends:
      0x80  (a 1-bit followed by 7 zero-bits)
      zero bytes until len(padded) ≡ block_size - 8 (mod block_size)
      64-bit big-endian encoding of the original message length IN BITS

    The total padded length is always a multiple of block_size.
    block_size must be >= 9 (to hold at least the 0x80 + 8-byte length).
    """
    if block_size < 9:
        raise ValueError("md_pad: block_size must be >= 9")

    msg_len_bits = len(message) * 8
    # Start with the 0x80 byte
    padded = bytearray(message) + bytearray(b"\x80")
    # Pad with zeros until length ≡ block_size - 8 (mod block_size)
    target_mod = block_size - 8
    while len(padded) % block_size != target_mod:
        padded += b"\x00"
    # Append 64-bit big-endian length
    padded += struct.pack(">Q", msg_len_bits)
    assert len(padded) % block_size == 0
    return bytes(padded)


def md_unpad(padded: bytes, block_size: int) -> bytes:
    """Remove Merkle-Damgård padding (used in tests)."""
    if len(padded) % block_size != 0:
        raise ValueError("md_unpad: padded length not a multiple of block_size")
    # Strip the 8-byte length field
    without_len = padded[:-8]
    # Strip trailing zeros and the 0x80 byte
    idx = without_len.rfind(b"\x80")
    if idx == -1:
        raise ValueError("md_unpad: no 0x80 byte found")
    return bytes(without_len[:idx])


# ─────────────────────────────────────────────────────────────
#  PKCS#1 v1.5 Encryption Padding (PA#12)
# ─────────────────────────────────────────────────────────────

def pkcs1_v15_pad(message: bytes, n_bytes: int) -> bytes:
    """Apply PKCS#1 v1.5 encryption padding.

    Structure: 0x00 || 0x02 || PS || 0x00 || M
    where PS is at least 8 non-zero random bytes.
    Total length == n_bytes.
    """
    from src.common.randomness import random_nonzero_bytes

    m_len = len(message)
    if m_len > n_bytes - 11:
        raise ValueError(
            f"pkcs1_v15_pad: message too long ({m_len} bytes) for {n_bytes}-byte modulus"
        )
    ps_len = n_bytes - m_len - 3
    ps = random_nonzero_bytes(ps_len)
    return b"\x00\x02" + ps + b"\x00" + message


def pkcs1_v15_unpad(padded: bytes) -> bytes:
    """Remove PKCS#1 v1.5 encryption padding.

    Returns the message or raises ValueError on malformed padding.
    In a real system this would return ⊥ (bottom); here we raise.
    """
    if len(padded) < 11:
        raise ValueError("pkcs1_v15_unpad: ciphertext too short")
    if padded[0:2] != b"\x00\x02":
        raise ValueError("pkcs1_v15_unpad: invalid header bytes")
    # Find the 0x00 separator after PS
    sep_idx = padded.find(b"\x00", 2)
    if sep_idx == -1:
        raise ValueError("pkcs1_v15_unpad: no separator 0x00 found")
    ps = padded[2:sep_idx]
    if len(ps) < 8:
        raise ValueError("pkcs1_v15_unpad: PS too short (< 8 bytes)")
    return padded[sep_idx + 1 :]


# ─────────────────────────────────────────────────────────────
#  ISO/IEC 7816 Block Padding (for CBC-MAC, PA#5)
# ─────────────────────────────────────────────────────────────

def iso7816_pad(message: bytes, block_size: int) -> bytes:
    """Pad message to a multiple of block_size using ISO/IEC 7816-4 method 2.

    Appends 0x80 followed by zero bytes.
    """
    padded = bytearray(message) + b"\x80"
    while len(padded) % block_size != 0:
        padded += b"\x00"
    return bytes(padded)


def iso7816_unpad(padded: bytes) -> bytes:
    """Remove ISO/IEC 7816-4 method 2 padding."""
    idx = padded.rfind(b"\x80")
    if idx == -1:
        raise ValueError("iso7816_unpad: no 0x80 byte found")
    # Everything after 0x80 must be zeros
    if any(b != 0 for b in padded[idx + 1 :]):
        raise ValueError("iso7816_unpad: non-zero bytes after 0x80")
    return padded[:idx]


# ─────────────────────────────────────────────────────────────
#  Zero Padding (simple, for fixed-length PRF inputs)
# ─────────────────────────────────────────────────────────────

def zero_pad(data: bytes, target_len: int) -> bytes:
    """Right-pad data with zeros to exactly target_len bytes."""
    if len(data) > target_len:
        raise ValueError(f"zero_pad: data length {len(data)} > target {target_len}")
    return data + b"\x00" * (target_len - len(data))


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """PKCS#7 padding: append N bytes each with value N."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    if not data:
        raise ValueError("pkcs7_unpad: empty input")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError("pkcs7_unpad: invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("pkcs7_unpad: padding bytes incorrect")
    return data[:-pad_len]
