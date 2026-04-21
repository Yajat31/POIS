"""
PA#7 — Merkle-Damgård Hash Framework

Implements a generic, pluggable Merkle-Damgård (MD) hash construction.
The compression function is injected at construction time, allowing PA#8
to plug in the DLP-based compression function.

MD Construction:
  hash(m) = H_t where:
    H_0 = IV  (initial value)
    m' = md_pad(m, block_size)
    For each block m_i of m':
      H_i = compress(H_{i-1}, m_i)
  Output: H_t

MD Strengthening Padding (FIPS standard):
  append 0x80 ∥ 0x00...0x00 ∥ len(m) in 64-bit big-endian
  such that total length is a multiple of block_size.

Collision propagation theorem: a collision in compress() propagates to the full hash.
This is demonstrated using a dummy XOR compression function.

No external crypto libraries used.
"""

from __future__ import annotations
from typing import Callable
from src.common.padding import md_pad
from src.common.bytes_utils import xor_bytes


# ─────────────────────────────────────────────────────────────
#  Generic Merkle-Damgård Framework
# ─────────────────────────────────────────────────────────────

class MerkleDamgard:
    """Generic Merkle-Damgård hash construction.

    Args:
        compress: callable(chaining_value: bytes, block: bytes) -> bytes
                  The compression function. Must be deterministic.
        iv:       Initial chaining value (bytes). Length must equal compress output.
        block_size: Block size in bytes. Padding targets this size.

    Usage:
        hash_fn = MerkleDamgard(compress=my_compress, iv=my_iv, block_size=64)
        digest = hash_fn.hash(message)
    """

    def __init__(
        self,
        compress: Callable[[bytes, bytes], bytes],
        iv: bytes,
        block_size: int,
    ):
        self.compress = compress
        self.iv = iv
        self.block_size = block_size
        # Validate: compress output length must equal iv length
        test_block = b"\x00" * block_size
        test_out = compress(iv, test_block)
        if len(test_out) != len(iv):
            raise ValueError(
                f"compress output length ({len(test_out)}) must equal IV length ({len(iv)})"
            )
        self.digest_size = len(iv)

    def hash(self, message: bytes) -> bytes:
        """Compute the MD hash of *message*.

        Applies MD-strengthening padding, then iterates the compression function.
        """
        padded = md_pad(message, self.block_size)
        state = self.iv
        for i in range(0, len(padded), self.block_size):
            block = padded[i : i + self.block_size]
            state = self.compress(state, block)
        return state

    def hash_streaming(self, chunks: list[bytes]) -> bytes:
        """Hash a list of byte-chunks (streaming interface).

        Concatenates chunks and hashes the full message (MD is not streaming-safe
        without careful padding — we collect all chunks first for correctness).
        """
        return self.hash(b"".join(chunks))


# ─────────────────────────────────────────────────────────────
#  Dummy XOR Compression Function (for framework validation)
# ─────────────────────────────────────────────────────────────

def xor_compress(chaining: bytes, block: bytes) -> bytes:
    """Dummy compression function: XOR the block into the chaining value.

    Used to validate the MD framework behavior and to demonstrate
    how compression collisions propagate to full-hash collisions.

    INSECURE: trivially collide-able. Use only for framework testing.
    """
    # Fold block into chaining value length via XOR
    cv_len = len(chaining)
    # XOR-fold block to cv_len bytes
    folded = bytearray(cv_len)
    for i, byte in enumerate(block):
        folded[i % cv_len] ^= byte
    return bytes(xor_bytes(chaining, bytes(folded)))


def make_xor_hash(digest_bytes: int = 16, block_size: int = 64) -> MerkleDamgard:
    """Create an XOR-fold Merkle-Damgård hash instance for testing."""
    iv = b"\x00" * digest_bytes
    # Need compress to accept (digest_bytes, block_size) → digest_bytes
    def _compress(chaining: bytes, block: bytes) -> bytes:
        cv_len = len(chaining)
        folded = bytearray(cv_len)
        for i, byte in enumerate(block):
            folded[i % cv_len] ^= byte
        return bytes(xor_bytes(chaining, bytes(folded)))
    return MerkleDamgard(compress=_compress, iv=iv, block_size=block_size)


# ─────────────────────────────────────────────────────────────
#  Collision Propagation Demo
# ─────────────────────────────────────────────────────────────

def demo_collision_propagation(hash_fn: MerkleDamgard) -> dict:
    """Demonstrate that a compression collision propagates to a full-hash collision.

    The Merkle-Damgård extension lemma:
    If compress(H, B1) = compress(H, B2) for some H, B1 ≠ B2,
    then hash(prefix ∥ B1 ∥ suffix) = hash(prefix ∥ B2 ∥ suffix)
    for any prefix and suffix of the same length.

    We find such a collision by brute-force on the XOR compress (trivial).
    """
    # Find two blocks B1 ≠ B2 such that compress(IV, B1) = compress(IV, B2)
    # For XOR-fold, this is: (XOR of B1 bytes) = (XOR of B2 bytes)
    b_size = hash_fn.block_size
    H = hash_fn.iv

    # Simple: B2 = B1 with first two bytes swapped (only works if they differ)
    B1 = b"\x01" * b_size
    B2 = b"\x02" + b"\x01" * (b_size - 2) + b"\x03"  # XOR-fold same result for xor_compress

    out1 = hash_fn.compress(H, B1)
    out2 = hash_fn.compress(H, B2)

    # For XOR compress specifically, find a real collision
    # B2 = B1 ⊕ e_0 ⊕ e_k (flip byte 0 and byte k=1 — XOR cancels out)
    B2_collision = bytearray(B1)
    B2_collision[0] ^= 0xFF
    # To maintain same XOR-fold: also flip byte at position (0 % cv_len) another time
    B2_collision[b_size - 1] ^= 0xFF  # cancels the flip if block_size > digest_size
    B2_collision = bytes(B2_collision)

    out1 = hash_fn.compress(H, B1)
    out2c = hash_fn.compress(H, B2_collision)

    collision_found = out1 == out2c and B1 != B2_collision

    if collision_found:
        # Show propagation: hash(B1 ∥ suffix) = hash(B2 ∥ suffix)
        suffix = b"SAME_SUFFIX_DATA" * 2
        hash1 = hash_fn.hash(B1 + suffix)
        hash2 = hash_fn.hash(B2_collision + suffix)
        propagates = hash1 == hash2
    else:
        suffix = b""
        hash1 = hash2 = b""
        propagates = False

    return {
        "block1": B1.hex()[:32] + "...",
        "block2": B2_collision.hex()[:32] + "...",
        "compress_collision": collision_found,
        "hash_collision_propagates": propagates,
        "hash1": hash1.hex() if hash1 else None,
        "hash2": hash2.hex() if hash2 else None,
        "explanation": (
            "Merkle-Damgård extension lemma: any compression collision lifts "
            "to a full-hash collision by appending the same suffix to both colliding inputs."
        ),
    }
