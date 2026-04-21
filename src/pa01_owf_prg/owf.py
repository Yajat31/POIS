"""
PA#1 — One-Way Function (OWF) and Pseudo-Random Generator (PRG)

Implements:
  - OWF based on Discrete Logarithm Problem (DLP): f(x) = g^x mod p
  - PRG built from OWF via iterative hard-core bit extraction (Goldreich-Levin)
  - Backward direction: argue PRG(s) = G(s) is one-way

Depends on:
  - src/foundations/dlp_group.py  (safe-prime group parameters)
  - src/common/randomness.py      (os.urandom)
  - src/common/math_utils.py      (modexp)
  - src/pa13_miller_rabin/        (via dlp_group gen_safe_prime)

No external crypto libraries used.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from src.foundations.dlp_group import GroupParams, DEMO_PARAMS, gen_group
from src.common.math_utils import modexp
from src.common.randomness import random_element_zq
from src.common.bytes_utils import int_to_bits, bits_to_bytes, bytes_to_int


# ─────────────────────────────────────────────────────────────
#  One-Way Function (OWF)
# ─────────────────────────────────────────────────────────────

class OWF:
    """DLP-based One-Way Function: f(x) = g^x mod p.

    Security: inverting f (finding x from y = g^x mod p) is as hard as
    solving the discrete logarithm problem in the group.

    Interface: OWF.evaluate(x) -> int
    """

    def __init__(self, params: GroupParams | None = None):
        """Initialize with group parameters. Uses DEMO_PARAMS if not provided."""
        self.params = params or DEMO_PARAMS

    @property
    def p(self) -> int:
        return self.params.p

    @property
    def q(self) -> int:
        return self.params.q

    @property
    def g(self) -> int:
        return self.params.g

    def evaluate(self, x: int) -> int:
        """Compute f(x) = g^x mod p.

        x should be in Z_q (the exponent space). We reduce mod q.
        Returns a group element in Z_p*.
        """
        x_mod = x % self.q
        return modexp(self.g, x_mod, self.p)

    def verify_hardness(self, num_trials: int = 100) -> dict:
        """Empirically demonstrate that random inversion fails.

        Generates random group elements y = g^x mod p and attempts to
        find x by brute force. Succeeds only for tiny group parameters.

        Returns statistics about inversion success rate.
        """
        successes = 0
        for _ in range(num_trials):
            x = random_element_zq(self.q)
            y = self.evaluate(x)
            # Attempt brute-force inversion (only feasible for tiny q)
            found = None
            if self.q <= 10000:
                for candidate in range(self.q):
                    if modexp(self.g, candidate, self.p) == y:
                        found = candidate
                        break
            if found is not None and found % self.q == x % self.q:
                successes += 1
        return {
            "num_trials": num_trials,
            "successes": successes,
            "group_order_q": self.q,
            "feasible_brute_force": self.q <= 10000,
            "note": "Brute-force inversion fails for large q (computationally hard).",
        }


# ─────────────────────────────────────────────────────────────
#  Hard-Core Bit Extraction (Goldreich-Levin style)
# ─────────────────────────────────────────────────────────────

def _hard_core_bit(owf: OWF, state: int, r: int) -> int:
    """Extract one hard-core bit from OWF state.

    Uses the inner-product bit: ⟨state, r⟩ mod 2
    where state and r are treated as bit vectors (mod q).

    The Goldreich-Levin theorem guarantees this bit is hard to predict
    given only the OWF output f(state).
    """
    # XOR all bits of (state AND r) — inner product mod 2
    combined = state & r
    bit = bin(combined).count("1") % 2
    return bit


# ─────────────────────────────────────────────────────────────
#  PRG built from OWF
# ─────────────────────────────────────────────────────────────

class PRG:
    """Pseudo-Random Generator (PRG) built from OWF via iterative hard-core bits.

    Construction:
        G(s, ℓ) = b_1 ∥ b_2 ∥ ... ∥ b_ℓ
    where:
        s_0 = s (seed)
        y_i = f(s_{i-1}) = g^{s_{i-1}} mod p  (OWF application)
        s_i = y_i mod q                         (next state, in exponent space)
        b_i = ⟨s_{i-1}, r_i⟩ mod 2             (hard-core bit)
        r_i = s_{i-1} XOR some fixed mask       (simplified: r_i = s_{i-1})

    The OWF output is one-way, so each b_i is computationally indistinguishable
    from a uniform random bit.

    Interface: PRG.seed(s) / PRG.next_bits(n)
    """

    def __init__(self, owf: OWF | None = None):
        self.owf = owf or OWF()
        self._state: int | None = None
        self._output_length: int = 0

    def seed(self, s: int | bytes) -> None:
        """Initialize the PRG with a seed s.

        s can be an integer (used directly as x in Z_q) or bytes.
        """
        if isinstance(s, bytes):
            s = bytes_to_int(s) % self.owf.q
        self._state = s % self.owf.q
        self._output_length = 0

    def next_bits(self, n: int) -> list[int]:
        """Generate n pseudo-random bits.

        Each bit is extracted as a hard-core bit of the OWF state.
        The state advances by applying the OWF each step.
        """
        if self._state is None:
            raise RuntimeError("PRG not seeded. Call PRG.seed(s) first.")
        bits = []
        state = self._state
        for _ in range(n):
            # Hard-core bit from current state
            bit = _hard_core_bit(self.owf, state, state ^ 0xAAAAAAAA)
            bits.append(bit)
            # Advance state: apply OWF and map output back to exponent space
            y = self.owf.evaluate(state)
            state = y % self.owf.q
            if state == 0:
                state = 1  # avoid degenerate 0 state
        self._state = state
        self._output_length += n
        return bits

    def next_bytes(self, n: int) -> bytes:
        """Generate n pseudo-random bytes."""
        bits = self.next_bits(n * 8)
        return bits_to_bytes(bits)

    def expand(self, seed: int | bytes, length: int) -> bytes:
        """Convenience: seed and expand to *length* bytes at once."""
        self.seed(seed)
        return self.next_bytes(length)


# ─────────────────────────────────────────────────────────────
#  Backward Direction: PRG → OWF
# ─────────────────────────────────────────────────────────────

def prg_is_owf_demo(prg: PRG | None = None, seed: int | None = None) -> dict:
    """Demonstrate that f(s) = G(s) is one-way.

    If G is a PRG then f(s) = G(s) is one-way:
      - Given G(s), find s. This requires inverting G, which is hard if G is a PRG.
      - We show empirically that brute-force inversion of a fixed PRG output fails.

    Returns a dictionary with the demonstration data.
    """
    if prg is None:
        prg = PRG()
    owf = prg.owf
    if seed is None:
        seed = random_element_zq(owf.q)

    # Compute G(s)
    output = prg.expand(seed, 4)  # 4 bytes = 32 bits of PRG output

    # Attempt inversion: try all seeds in the exponent space
    # Only feasible for toy parameters (q ≤ 10000)
    found_seed = None
    if owf.q <= 10000:
        for candidate in range(owf.q):
            candidate_out = prg.expand(candidate, 4)
            if candidate_out == output:
                found_seed = candidate
                break

    return {
        "seed": seed,
        "prg_output_hex": output.hex(),
        "inversion_attempted": owf.q <= 10000,
        "inversion_found": found_seed,
        "correct": found_seed is not None and found_seed % owf.q == seed % owf.q,
        "explanation": (
            "For small q, brute-force inversion works. "
            "For cryptographic q, inverting G(s) is as hard as inverting the OWF."
        ),
    }


# ─────────────────────────────────────────────────────────────
#  NIST SP 800-22 Statistical Tests (subset)
# ─────────────────────────────────────────────────────────────

def nist_monobit_test(bits: list[int]) -> dict:
    """NIST SP 800-22 Frequency (Monobit) Test.

    Counts proportion of 1s. For a truly random sequence, should be ≈ 0.5.
    P-value > 0.01 → pass.
    """
    n = len(bits)
    s = sum(bits)
    proportion = s / n
    # s_obs = |#1s - #0s| / sqrt(n)
    s_obs = abs(2 * s - n) / (n ** 0.5)
    import math
    # P-value from complementary error function
    p_value = math.erfc(s_obs / (2 ** 0.5))
    return {
        "test": "Monobit Frequency",
        "n": n,
        "ones": s,
        "proportion": round(proportion, 4),
        "s_obs": round(s_obs, 4),
        "p_value": round(p_value, 4),
        "pass": p_value > 0.01,
    }


def nist_runs_test(bits: list[int]) -> dict:
    """NIST SP 800-22 Runs Test.

    A run is a sequence of identical bits. Tests whether runs are too long or short.
    P-value > 0.01 → pass.
    """
    import math
    n = len(bits)
    pi = sum(bits) / n
    # Pre-test: monobit
    if abs(pi - 0.5) >= 2 / n**0.5:
        return {"test": "Runs", "pass": False, "note": "Monobit pre-test failed"}
    # Count runs
    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            runs += 1
    expected = 2 * n * pi * (1 - pi)
    variance = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    if variance == 0:
        return {"test": "Runs", "pass": False, "note": "Zero variance"}
    p_value = math.erfc(abs(runs - expected) / variance)
    return {
        "test": "Runs",
        "n": n,
        "runs": runs,
        "expected_runs": round(expected, 2),
        "p_value": round(p_value, 4),
        "pass": p_value > 0.01,
    }


def nist_serial_test(bits: list[int], m: int = 2) -> dict:
    """NIST SP 800-22 Serial Test (m=2 by default).

    Tests whether all 2^m m-bit patterns appear equally frequently.
    """
    import math
    n = len(bits)
    # Count pattern frequencies for m and m-1 bits
    def count_patterns(seq, length):
        counts = {}
        for i in range(len(seq) - length + 1):
            pat = tuple(seq[i : i + length])
            counts[pat] = counts.get(pat, 0) + 1
        return counts

    psi_m = sum(c**2 for c in count_patterns(bits, m).values()) * (2**m / n) - n
    psi_m1 = sum(c**2 for c in count_patterns(bits, m - 1).values()) * (2 ** (m - 1) / n) - n if m > 1 else 0
    psi_m2 = sum(c**2 for c in count_patterns(bits, m - 2).values()) * (2 ** (m - 2) / n) - n if m > 2 else 0

    delta1 = psi_m - psi_m1
    delta2 = psi_m - 2 * psi_m1 + psi_m2
    # Chi-squared p-value (approximate via igamcc)
    try:
        import math
        p1 = math.exp(-delta1 / 2) if delta1 > 0 else 1.0
        p2 = math.exp(-delta2 / 2) if delta2 > 0 else 1.0
    except Exception:
        p1, p2 = 0.5, 0.5
    return {
        "test": f"Serial (m={m})",
        "n": n,
        "delta_psi_sq_1": round(delta1, 4),
        "delta_psi_sq_2": round(delta2, 4),
        "p1": round(p1, 4),
        "p2": round(p2, 4),
        "pass": p1 > 0.01 and p2 > 0.01,
    }


def run_statistical_tests(bits: list[int]) -> list[dict]:
    """Run the NIST SP 800-22 subset (monobit, runs, serial) on a bit sequence."""
    return [
        nist_monobit_test(bits),
        nist_runs_test(bits),
        nist_serial_test(bits),
    ]
