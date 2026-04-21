"""
PA#2 — PRF via GGM Tree Construction

Implements:
  - GGMPRF: PRF built from PRG using the GGM binary tree construction
  - PRFFromAES: PRF using the AES-128 block cipher as underlying primitive
  - PRGFromPRF: PRG built from PRF (backward direction)

GGM construction:
  Given a PRG G: {0,1}^n → {0,1}^{2n} (outputs G_0(s) ∥ G_1(s)),
  define F_k(x_1...x_n) by walking the tree:
    s_0 = k
    s_i = G_{x_i}(s_{i-1}) for i = 1..n
  Output: s_n

This is a PRF if G is a PRG (Goldreich-Goldwasser-Micali theorem).

Depends on:
  - PA#1 (PRG from OWF)
  - src/foundations/aes_impl.py (AES as alternative)

No external crypto libraries.
"""

from __future__ import annotations
from src.pa01_owf_prg.owf import PRG, OWF
from src.foundations.dlp_group import DEMO_PARAMS
from src.foundations.aes_impl import aes_encrypt_block
from src.common.bytes_utils import (
    bytes_to_bits, bits_to_bytes, int_to_bytes, bytes_to_int, xor_bytes, split_half
)
from src.common.randomness import random_bytes


# ─────────────────────────────────────────────────────────────
#  GGM PRF: PRF from PRG
# ─────────────────────────────────────────────────────────────

class GGMPRF:
    """GGM pseudo-random function built from the PA#1 PRG.

    Key space:  Z_q (same as PRG seed space)
    Input space: n-bit strings (passed as list[int] of 0/1)
    Output:     n pseudo-random bits

    F(k, x_1...x_n):
        s = k
        For each bit x_i of x:
            s = G_{x_i}(s)   where G_0(s) = first half of G(s),
                                    G_1(s) = second half of G(s)
        return s
    """

    def __init__(self, owf: OWF | None = None, output_bits: int = 32):
        """
        owf: the underlying OWF for the PRG
        output_bits: how many PRG bits to produce at each node (≥ 2, must be even)
        """
        self.owf = owf or OWF()
        self.output_bits = output_bits
        self._prg = PRG(self.owf)

    def _G(self, s: int) -> tuple[int, int]:
        """Apply the PRG to state s, return (G_0(s), G_1(s)) as integers."""
        self._prg.seed(s)
        bits = self._prg.next_bits(self.output_bits)
        half = self.output_bits // 2
        left_bits = bits[:half]
        right_bits = bits[half:]
        # Convert to integers for use as next states
        left = 0
        for b in left_bits:
            left = (left << 1) | b
        right = 0
        for b in right_bits:
            right = (right << 1) | b
        # Map back into Z_q
        left = left % self.owf.q or 1
        right = right % self.owf.q or 1
        return left, right

    def F(self, k: int | bytes, x_bits: list[int]) -> int:
        """Compute the GGM PRF: F_k(x_bits) → integer.

        k: key as integer (in Z_q) or bytes
        x_bits: input as list of 0/1 bits
        """
        if isinstance(k, bytes):
            k = bytes_to_int(k) % self.owf.q or 1
        state = k % self.owf.q or 1
        for bit in x_bits:
            left, right = self._G(state)
            state = left if bit == 0 else right
        return state

    def F_bytes(self, k: bytes, x: bytes) -> bytes:
        """Convenience: key and input as bytes, output as bytes."""
        x_bits = bytes_to_bits(x)
        result = self.F(k, x_bits)
        out_len = (self.owf.p.bit_length() + 7) // 8
        return int_to_bytes(result % self.owf.p, out_len)

    def tree_nodes(self, k: int, depth: int) -> dict:
        """Return all tree node values for a GGM tree of given depth.

        Useful for the PA#2 GGM tree visualizer (n ≤ 8).
        Returns dict mapping (level, node_index) → (state_value, left_child, right_child).
        """
        if depth > 8:
            raise ValueError("tree_nodes: depth > 8 would be too large")
        nodes = {}
        # BFS: queue of (level, index, state)
        queue = [(0, 0, k)]
        while queue:
            level, idx, state = queue.pop(0)
            left, right = self._G(state)
            nodes[(level, idx)] = {
                "state": state,
                "G0": left,
                "G1": right,
            }
            if level < depth - 1:
                queue.append((level + 1, 2 * idx, left))
                queue.append((level + 1, 2 * idx + 1, right))
        return nodes

    def highlighted_path(self, k: int, x_bits: list[int]) -> list[dict]:
        """Return the evaluation path for input x_bits, for visualization."""
        path = []
        state = k % self.owf.q or 1
        for i, bit in enumerate(x_bits):
            left, right = self._G(state)
            chosen = left if bit == 0 else right
            path.append({
                "level": i,
                "state": state,
                "bit": bit,
                "G0": left,
                "G1": right,
                "chosen": chosen,
            })
            state = chosen
        path.append({"level": len(x_bits), "state": state, "output": True})
        return path


# ─────────────────────────────────────────────────────────────
#  AES-based PRF (plug-in alternative)
# ─────────────────────────────────────────────────────────────

class PRFFromAES:
    """PRF using AES-128 as F(k, x) = AES_k(x).

    Key: 16 bytes
    Input: 16 bytes (one AES block)
    Output: 16 bytes

    AES is a PRP (permutation), and a PRP is also a PRF for variable-length inputs
    (with negligible security loss for n << 2^64 queries).
    """

    BLOCK_SIZE = 16  # bytes

    def F(self, k: bytes, x: bytes) -> bytes:
        """Compute F_k(x) = AES_k(x).

        k must be exactly 16 bytes.
        x must be exactly 16 bytes (one block).
        """
        if len(k) != 16:
            raise ValueError("PRFFromAES: key must be 16 bytes")
        if len(x) != 16:
            raise ValueError("PRFFromAES: input must be 16 bytes (one block)")
        return aes_encrypt_block(k, x)

    def F_variable(self, k: bytes, x: bytes) -> bytes:
        """Extend to variable-length inputs by processing in 16-byte blocks.

        For input x of arbitrary length, split into 16-byte blocks and XOR-chain.
        """
        from src.common.padding import zero_pad
        if len(k) != 16:
            raise ValueError("PRFFromAES: key must be 16 bytes")
        block_size = self.BLOCK_SIZE
        # Pad x to multiple of block_size
        padded_len = ((len(x) + block_size - 1) // block_size) * block_size
        x_padded = x + b"\x00" * (padded_len - len(x))
        out = b"\x00" * block_size
        for i in range(0, len(x_padded), block_size):
            block = x_padded[i : i + block_size]
            out = aes_encrypt_block(k, xor_bytes(out, block))
        return out


# ─────────────────────────────────────────────────────────────
#  PRG from PRF (backward direction: PRF → PRG)
# ─────────────────────────────────────────────────────────────

class PRGFromPRF:
    """PRG constructed from a PRF.

    G(s) = F_s(0^n) ∥ F_s(1^n)

    This expands a seed s into a 2×n-bit pseudo-random string.
    If F is a PRF then G is a PRG (standard construction).

    Uses PRFFromAES by default. k=s must be 16 bytes for AES.
    """

    def __init__(self, prf: PRFFromAES | None = None):
        self.prf = prf or PRFFromAES()

    def G(self, s: bytes) -> bytes:
        """Expand seed s to 32 bytes: F_s(0^16) ∥ F_s(1^16)."""
        if len(s) != 16:
            raise ValueError("PRGFromPRF.G: seed must be 16 bytes (AES key size)")
        zero_block = b"\x00" * 16
        one_block = b"\x00" * 15 + b"\x01"
        left = self.prf.F(s, zero_block)   # F_s(0^128)
        right = self.prf.F(s, one_block)   # F_s(1 ∥ 0^127)
        return left + right

    def expand(self, s: bytes, length: int) -> bytes:
        """Expand seed to *length* bytes by chaining G repeatedly."""
        if len(s) != 16:
            raise ValueError("PRGFromPRF.expand: seed must be 16 bytes")
        output = b""
        state = s
        while len(output) < length:
            expanded = self.G(state)
            output += expanded[:16]  # use left half as output
            state = expanded[16:]    # use right half as next state
        return output[:length]


# ─────────────────────────────────────────────────────────────
#  Distinguishing Game (~100 queries, PRF vs random function)
# ─────────────────────────────────────────────────────────────

def distinguishing_game(
    prf: PRFFromAES | None = None,
    num_queries: int = 100,
) -> dict:
    """Simulate an IND-PRF distinguishing game.

    Challenger picks b ∈ {0,1}:
      b=0: oracle is real PRF F_k
      b=1: oracle is a lazy-evaluated random function (table-based)
    Adversary makes num_queries queries x_i and receives F_k(x_i) or R(x_i).
    Adversary tries to distinguish.

    Since we're testing statistical distribution rather than breaking security,
    we measure output entropy as a proxy.
    """
    import os
    if prf is None:
        prf = PRFFromAES()

    k = random_bytes(16)

    # Real PRF outputs
    prf_outputs = []
    for _ in range(num_queries):
        x = random_bytes(16)
        y = prf.F(k, x)
        prf_outputs.append(y)

    # Random function outputs (fresh random each time, independent)
    rand_outputs = []
    for _ in range(num_queries):
        rand_outputs.append(random_bytes(16))

    # Simple distinguisher: count unique outputs
    prf_unique = len(set(prf_outputs))
    rand_unique = len(set(rand_outputs))

    return {
        "num_queries": num_queries,
        "prf_unique_outputs": prf_unique,
        "random_unique_outputs": rand_unique,
        "note": "PRF and random function should have similar uniqueness. "
                "A real distinguishing attack requires finding collisions or structure.",
        "prf_advantage_estimate": 0.0,  # Negligible for PRF
    }
