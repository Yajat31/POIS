"""
PA#13 — Miller-Rabin Primality Testing

Implements:
  - modexp(a, e, n)        — square-and-multiply (also available in common/math_utils.py)
  - miller_rabin(n, k)     — returns True if n is PROBABLY PRIME, False if COMPOSITE
  - is_prime(n)            — public wrapper
  - gen_prime(bits)        — generate a probable prime of the given bit-length
  - gen_safe_prime(bits)   — generate a safe prime p = 2q+1 (both prime)

Required by: PA#11 (DH group setup), PA#12 (RSA key generation),
             PA#14 (CRT attack), PA#16 (ElGamal).

No external libraries used. Only os.urandom for randomness.
"""

from src.common.randomness import random_odd_int, random_int
from src.common.math_utils import modexp as _modexp


def modexp(base: int, exp: int, mod: int) -> int:
    """Square-and-multiply modular exponentiation (delegates to common)."""
    return _modexp(base, exp, mod)


# ─────────────────────────────────────────────────────────────
#  Miller-Rabin Core
# ─────────────────────────────────────────────────────────────

def _decompose(n_minus_1: int) -> tuple[int, int]:
    """Write n-1 = 2^s * d with d odd. Returns (s, d)."""
    s = 0
    d = n_minus_1
    while d % 2 == 0:
        d //= 2
        s += 1
    return s, d


def miller_rabin(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test.

    Args:
        n: integer to test (must be >= 2)
        k: number of witness rounds (default 20 gives error prob < 4^{-20})

    Returns:
        True  → n is PROBABLY PRIME
        False → n is COMPOSITE (definite)

    Algorithm:
        Write n-1 = 2^s * d (d odd).
        For k random witnesses a ∈ [2, n-2]:
            Compute x = a^d mod n
            If x == 1 or x == n-1: continue (witness doesn't help)
            Repeat s-1 times: x = x^2 mod n
                if x == n-1: break (witness doesn't help)
            else: return COMPOSITE
        return PROBABLY PRIME
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    s, d = _decompose(n - 1)

    for _ in range(k):
        a = random_int(2, n - 2)
        x = modexp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = modexp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # Composite (definite)

    return True  # Probably prime


def is_prime(n: int, k: int = 20) -> bool:
    """Public wrapper for Miller-Rabin. Returns True if n is probably prime."""
    return miller_rabin(n, k)


# ─────────────────────────────────────────────────────────────
#  Prime Generation
# ─────────────────────────────────────────────────────────────

def gen_prime(bits: int, k: int = 20) -> int:
    """Generate a random probable prime of exactly *bits* bits.

    Uses random_odd_int to generate candidates and tests with Miller-Rabin.
    """
    if bits < 2:
        raise ValueError("gen_prime: bits must be >= 2")
    while True:
        candidate = random_odd_int(bits)
        if miller_rabin(candidate, k):
            return candidate


def gen_safe_prime(bits: int, k: int = 20) -> tuple[int, int]:
    """Generate a safe prime p = 2q + 1 where both p and q are probably prime.

    Returns (p, q).
    bits is the desired bit-length of p.
    """
    if bits < 3:
        raise ValueError("gen_safe_prime: bits must be >= 3")
    q_bits = bits - 1
    while True:
        q = gen_prime(q_bits, k)
        p = 2 * q + 1
        if miller_rabin(p, k):
            return p, q


# ─────────────────────────────────────────────────────────────
#  Demo: Carmichael Number 561 — passes Fermat, fails Miller-Rabin
# ─────────────────────────────────────────────────────────────

def fermat_test(n: int, k: int = 20) -> bool:
    """Fermat primality test (INSECURE — Carmichael numbers fool it).

    Returns True if n passes k Fermat rounds (probably prime — WRONG for Carmichaels).
    """
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for _ in range(k):
        a = random_int(2, n - 2)
        if modexp(a, n - 1, n) != 1:
            return False
    return True


def demo_carmichael_561() -> dict:
    """Demonstrate that 561 passes Fermat but is correctly rejected by Miller-Rabin.

    561 = 3 × 11 × 17 is the smallest Carmichael number.
    For all a coprime to 561: a^560 ≡ 1 (mod 561) — yet 561 is composite.
    """
    n = 561
    # Run Fermat with fixed witnesses to show it passes
    fermat_results = []
    for a in [2, 5, 7, 11, 13]:
        result = modexp(a, n - 1, n)
        fermat_results.append({"witness": a, "a^(n-1) mod n": result, "passes": result == 1})

    # Miller-Rabin will correctly detect composite
    # n-1 = 560 = 2^4 * 35
    s, d = _decompose(n - 1)
    mr_result = miller_rabin(n, k=40)

    return {
        "n": n,
        "factorization": "3 × 11 × 17",
        "is_composite": True,
        "n_minus_1_decomposition": f"2^{s} * {d}",
        "fermat_witnesses": fermat_results,
        "fermat_says_prime": True,  # always True for Carmichael numbers
        "miller_rabin_says_prime": mr_result,  # should be False
        "miller_rabin_correct": not mr_result,
    }


# ─────────────────────────────────────────────────────────────
#  Performance Benchmark
# ─────────────────────────────────────────────────────────────

def benchmark_gen_prime(bits_list: list[int] = None, trials: int = 3) -> list[dict]:
    """Benchmark prime generation at various bit sizes."""
    import time
    if bits_list is None:
        bits_list = [512, 1024, 2048]
    results = []
    for bits in bits_list:
        times = []
        for _ in range(trials):
            start = time.perf_counter()
            gen_prime(bits)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        avg = sum(times) / len(times)
        results.append({
            "bits": bits,
            "avg_seconds": round(avg, 4),
            "trials": trials,
        })
    return results
