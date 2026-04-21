"""
math_utils.py — Core arithmetic primitives.

Implements all modular arithmetic from scratch:
  - Square-and-multiply modular exponentiation
  - Extended Euclidean algorithm
  - Modular inverse
  - Integer e-th root (Newton's method, for Håstad attack)
  - Legendre symbol / Jacobi symbol (used in primality work)

No external libraries used.
"""


def modexp(base: int, exp: int, mod: int) -> int:
    """Square-and-multiply modular exponentiation: base^exp mod mod.

    Required by PA#12 (RSA), PA#13 (Miller-Rabin), PA#15 (Sign/Verify).
    Python's built-in pow(b,e,m) is permitted (it uses the same algorithm),
    but we implement manually to satisfy the assignment requirement.
    """
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm.

    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
    """
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def gcd(a: int, b: int) -> int:
    """Greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a: int, n: int) -> int:
    """Modular inverse of a mod n via extended GCD.

    Returns x such that a*x ≡ 1 (mod n).
    Raises ValueError if the inverse does not exist.
    """
    g, x, _ = extended_gcd(a % n, n)
    if g != 1:
        raise ValueError(f"mod_inverse: {a} has no inverse mod {n} (gcd={g})")
    return x % n


def lcm(a: int, b: int) -> int:
    """Least common multiple."""
    return abs(a * b) // gcd(a, b)


def jacobi_symbol(a: int, n: int) -> int:
    """Jacobi symbol (a/n). n must be a positive odd integer.

    Returns -1, 0, or 1. Used in primality testing utilities.
    """
    if n <= 0 or n % 2 == 0:
        raise ValueError("jacobi_symbol: n must be a positive odd integer")
    a = a % n
    result = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a = a % n
    return result if n == 1 else 0


def integer_nth_root(x: int, n: int) -> int:
    """Compute floor(x^(1/n)) using Newton's method.

    Used in PA#14 (Håstad attack: find e-th root of c mod nothing — just over Z).
    """
    if x < 0:
        raise ValueError("integer_nth_root: x must be non-negative")
    if x == 0:
        return 0
    if n == 1:
        return x
    # Initial estimate
    # Use bit-length heuristic for a reasonable starting guess
    bit_len = x.bit_length()
    estimate = 1 << ((bit_len + n - 1) // n)
    # Newton iterations: r = ((n-1)*r + x // r^(n-1)) // n
    while True:
        r_n_minus_1 = estimate ** (n - 1)
        next_estimate = ((n - 1) * estimate + x // r_n_minus_1) // n
        if next_estimate >= estimate:
            break
        estimate = next_estimate
    # Walk down to exact floor
    while estimate**n > x:
        estimate -= 1
    return estimate


def is_perfect_nth_power(x: int, n: int) -> tuple[bool, int]:
    """Check if x is a perfect n-th power. Returns (True, root) or (False, approx)."""
    root = integer_nth_root(x, n)
    return root**n == x, root


def crt_two(r1: int, m1: int, r2: int, m2: int) -> int:
    """Chinese Remainder Theorem for two congruences: x ≡ r1 (mod m1), x ≡ r2 (mod m2).

    Returns smallest non-negative x satisfying both, assuming gcd(m1,m2)=1.
    """
    g, u, v = extended_gcd(m1, m2)
    if g != 1:
        raise ValueError("crt_two: moduli must be coprime")
    # x = r1 + m1 * ((r2 - r1) * u mod m2)
    x = r1 + m1 * ((r2 - r1) * u % m2)
    return x % (m1 * m2)


def crt(residues: list[int], moduli: list[int]) -> int:
    """Chinese Remainder Theorem for multiple congruences.

    Returns smallest non-negative x such that x ≡ residues[i] (mod moduli[i]) for all i.
    Requires all moduli to be pairwise coprime.
    """
    if len(residues) != len(moduli):
        raise ValueError("crt: residues and moduli must have the same length")
    x = residues[0]
    m = moduli[0]
    for r, mod in zip(residues[1:], moduli[1:]):
        x = crt_two(x, m, r, mod)
        m *= mod
    return x % m
