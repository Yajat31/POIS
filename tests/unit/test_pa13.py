"""
Unit tests for PA#13 — Miller-Rabin Primality Testing

Tests:
  - 561 passes Fermat but fails Miller-Rabin (Carmichael number)
  - Small known primes pass Miller-Rabin
  - Small known composites fail Miller-Rabin
  - gen_prime generates primes of correct bit-length
  - gen_safe_prime generates valid safe primes
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from src.pa13_miller_rabin.miller_rabin import (
    miller_rabin, is_prime, gen_prime, gen_safe_prime,
    fermat_test, demo_carmichael_561, modexp,
)


class TestMillerRabin:
    def test_small_primes(self):
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 97, 101, 1009]:
            assert miller_rabin(p), f"{p} should be prime"

    def test_small_composites(self):
        for n in [4, 6, 8, 9, 10, 15, 21, 25, 100, 1000, 1001]:
            assert not miller_rabin(n), f"{n} should be composite"

    def test_carmichael_561(self):
        """561 passes Fermat (for witnesses coprime to 561) but fails Miller-Rabin.

        561 = 3 × 11 × 17.  Fermat's little theorem holds for all a coprime to 561,
        but our random Fermat test may occasionally pick a factor of 561 as witness.
        We verify the algebraic property directly and check Miller-Rabin rejects it.
        """
        from src.common.math_utils import modexp
        # Verify Fermat property holds for fixed witnesses coprime to 561
        n = 561
        for a in [2, 5, 7, 13, 17, 19, 23]:
            if n % a != 0:  # coprime witness
                assert modexp(a, n - 1, n) == 1, f"Fermat should hold for a={a} and n=561"
        # Miller-Rabin must correctly reject 561
        assert not miller_rabin(561, k=40), "561 should fail Miller-Rabin"

    def test_carmichael_demo(self):
        result = demo_carmichael_561()
        assert result["miller_rabin_correct"], "Miller-Rabin should correctly reject 561"
        assert result["fermat_says_prime"], "Fermat should incorrectly accept 561"

    def test_modexp_basic(self):
        assert modexp(2, 10, 1000) == 24
        assert modexp(3, 0, 7) == 1
        assert modexp(7, 1, 13) == 7

    def test_edge_cases(self):
        assert not miller_rabin(0)
        assert not miller_rabin(1)
        assert miller_rabin(2)
        assert miller_rabin(3)
        assert not miller_rabin(4)


class TestGenPrime:
    def test_gen_prime_is_prime(self):
        for bits in [16, 32, 64]:
            p = gen_prime(bits)
            assert miller_rabin(p, k=20), f"gen_prime({bits}) should be prime"
            assert p.bit_length() == bits, f"gen_prime({bits}) should have {bits} bits"

    def test_gen_safe_prime(self):
        p, q = gen_safe_prime(bits=20)
        assert miller_rabin(p), "p should be prime"
        assert miller_rabin(q), "q should be prime"
        assert p == 2 * q + 1, "p should equal 2q+1"

    def test_is_prime_wrapper(self):
        assert is_prime(17)
        assert not is_prime(18)
        assert is_prime(104729)
