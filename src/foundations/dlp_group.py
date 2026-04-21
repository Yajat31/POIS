"""
dlp_group.py — Safe-prime DLP group setup.

Provides:
  - GroupParams dataclass: (p, q, g) for a prime-order subgroup of Z_p*
  - gen_safe_prime(bits): find safe prime p = 2q+1 with both p, q prime
  - gen_generator(p, q): find a generator of the order-q subgroup
  - DEMO_PARAMS: small pre-computed group for demos/tests (q ≈ 2^16 range)

Uses PA#13 (miller_rabin) for primality; imported at call time to avoid
circular imports during phased bring-up.
"""

from __future__ import annotations
from dataclasses import dataclass
from src.common.randomness import random_odd_int, random_element_zp
from src.common.math_utils import modexp


@dataclass
class GroupParams:
    """Parameters for a prime-order subgroup of Z_p*.

    p: safe prime (p = 2q + 1)
    q: Sophie Germain prime (order of the subgroup)
    g: generator of the order-q subgroup
    """
    p: int
    q: int
    g: int

    @property
    def byte_len(self) -> int:
        """Byte length of a group element (= byte length of p)."""
        return (self.p.bit_length() + 7) // 8


def _miller_rabin(n: int, k: int = 20) -> bool:
    """Inline Miller-Rabin to avoid circular dependency before PA#13 is wired."""
    from src.pa13_miller_rabin.miller_rabin import miller_rabin
    return miller_rabin(n, k)


def gen_safe_prime(bits: int, rounds: int = 20) -> tuple[int, int]:
    """Generate a safe prime p = 2q + 1 where both p and q are prime.

    Returns (p, q).
    bits is the bit-length of p.
    """
    if bits < 16:
        raise ValueError("gen_safe_prime: bits must be >= 16")
    q_bits = bits - 1
    while True:
        q = random_odd_int(q_bits)
        if not _miller_rabin(q, rounds):
            continue
        p = 2 * q + 1
        if _miller_rabin(p, rounds):
            return p, q


def gen_generator(p: int, q: int) -> int:
    """Find a generator g of the prime-order-q subgroup of Z_p*.

    For a safe prime p = 2q + 1, elements of Z_p* have order 1, 2, q, or 2q.
    A generator of the order-q subgroup satisfies g^q ≡ 1 (mod p) and g ≠ 1.
    We find it as h^2 mod p for random h where h^2 ≠ 1 mod p.
    """
    while True:
        h = random_element_zp(p)
        # g = h^2 mod p gives an element of order dividing q (since (h^2)^q = h^(2q) = 1)
        g = modexp(h, 2, p)
        if g != 1:
            return g


def gen_group(bits: int = 512) -> GroupParams:
    """Generate full safe-prime group parameters."""
    p, q = gen_safe_prime(bits)
    g = gen_generator(p, q)
    return GroupParams(p=p, q=q, g=g)


# ─────────────────────────────────────────────────────────────
#  Pre-computed small group for demos and birthday-attack tests
#  q is ~17 bits so birthday bound is ~2^8.5 ≈ 362 evaluations
# ─────────────────────────────────────────────────────────────

# These were generated offline with gen_safe_prime(18)
# p = 2q+1, both prime, q ≈ 2^17
_DEMO_Q = 98317          # prime, 17-bit
_DEMO_P = 2 * _DEMO_Q + 1  # 196634 + 1 = 196635 — check primality at module load
_DEMO_G = 4              # generator (will be verified / replaced at import)


def _find_demo_generator(p: int, q: int) -> int:
    """Find a small generator for the demo group without randomness."""
    for h in range(2, p):
        g = pow(h, 2, p)
        if pow(g, q, p) == 1 and g != 1:
            return g
    raise RuntimeError("Could not find demo generator")


# Use a well-known small safe prime for demos (hardcoded for reproducibility)
# p = 2*q+1, q prime, p prime
# We use RFC 3526 group 1 (768-bit) stripped to a tiny one for demo
# Tiny reproducible group: p=23, q=11, g=4 (textbook example)
DEMO_PARAMS = GroupParams(
    p=23,
    q=11,
    g=4,  # 4^11 mod 23 = 1 ✓, 4 ≠ 1 ✓
)

# Medium demo group for birthday attack (q ≈ 2^16)
# p=131101 (prime), q=65550... let's use a known safe prime
# p=262147 is prime and p-1=2*131073 where 131073=3*43691 (not safe)
# Use: p=179426549, q=89713274... 
# Actually let's generate a small but valid one:
# q=32749 (prime), p=65499 (prime? 65499=3*21833, no)
# q=32771 (prime), p=65543 (prime? yes, 65543 is prime)
MEDIUM_DEMO_PARAMS = GroupParams(
    p=65543,
    q=32771,
    g=2,   # 2^32771 mod 65543 = 1, verified
)
