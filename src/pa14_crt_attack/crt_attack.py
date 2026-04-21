"""
PA#14 — CRT Optimization and Håstad's Broadcast Attack

Implements:
  - mod_inverse / crt from common (re-exported here for PA#14 interface)
  - rsa_dec_crt: CRT-based RSA decryption (~3-4x speedup)
  - integer_eth_root: Newton's method for e-th integer root
  - hastad_attack: recover plaintext from e ciphertexts under different moduli

Depends on: PA#12 (RSA), PA#13 (primes), src/common/math_utils.py
"""

from __future__ import annotations
from src.pa12_rsa.rsa import RSAPrivateKey, RSAPublicKey, rsa_dec
from src.common.math_utils import modexp, mod_inverse, crt, integer_nth_root
from src.common.bytes_utils import int_to_bytes


def rsa_dec_crt(sk: RSAPrivateKey, c: int) -> int:
    """CRT-accelerated RSA decryption using dp, dq, q_inv (Garner recombination).

    Speed: ~3-4x faster than naive m = c^d mod n.
    Correctness: rsa_dec_crt(sk, c) == rsa_dec(sk, c) for all valid c.
    """
    mp = modexp(c % sk.p, sk.dp, sk.p)  # c^dp mod p
    mq = modexp(c % sk.q, sk.dq, sk.q)  # c^dq mod q
    # Garner recombination: m = mp + p * ((mq - mp) * q_inv mod q ... wait)
    # Standard CRT: h = q_inv * (mp - mq) mod p; m = mq + q * h
    h = (sk.q_inv * (mp - mq)) % sk.p
    m = mq + sk.q * h
    return m


def crt_wrapper(residues: list[int], moduli: list[int]) -> int:
    """Wrapper exposing CRT from common math_utils."""
    return crt(residues, moduli)


def integer_eth_root(x: int, e: int) -> int:
    """Compute floor(x^(1/e)) using Newton's method."""
    return integer_nth_root(x, e)


def hastad_attack(ciphertexts: list[int], moduli: list[int], e: int) -> int:
    """Håstad's broadcast attack for low-exponent RSA.

    Given e ciphertexts C_i = m^e mod n_i (same m, different n_i, small e),
    recover m using CRT: combine residues to get X = m^e over Z,
    then take the integer e-th root.

    Requires: e recipients, all encrypted with exponent e, NO padding.

    Returns the recovered plaintext m as an integer.
    """
    if len(ciphertexts) < e:
        raise ValueError(f"hastad_attack: need at least {e} ciphertexts, got {len(ciphertexts)}")
    if len(ciphertexts) != len(moduli):
        raise ValueError("hastad_attack: must have one modulus per ciphertext")

    # Step 1: CRT to get X ≡ m^e (mod n_1 * n_2 * ... * n_e)
    X = crt(ciphertexts[:e], moduli[:e])

    # Step 2: Take integer e-th root of X
    m_recovered = integer_nth_root(X, e)

    # Verify: m^e should equal X
    if m_recovered ** e != X:
        raise ValueError(
            f"hastad_attack: integer {e}-th root check failed. "
            "Ensure moduli are pairwise coprime and m < min(n_i)."
        )
    return m_recovered


def demo_hastad_e3(bits: int = 128) -> dict:
    """Demonstrate Håstad's attack with e=3 and 3 recipients."""
    from src.pa12_rsa.rsa import rsa_keygen, rsa_enc

    m = 12345  # small plaintext for demo
    e = 3
    recipients = []
    for _ in range(e):
        pk, sk = rsa_keygen(bits, e=e)
        # Ensure m < n for each recipient
        while m >= pk.n:
            pk, sk = rsa_keygen(bits, e=e)
        c = rsa_enc(pk, m)
        recipients.append((pk, c))

    ciphertexts = [r[1] for r in recipients]
    moduli = [r[0].n for r in recipients]

    try:
        m_recovered = hastad_attack(ciphertexts, moduli, e)
        success = m_recovered == m
    except Exception as ex:
        m_recovered = None
        success = False
        error = str(ex)
    else:
        error = None

    return {
        "plaintext": m,
        "e": e,
        "num_recipients": e,
        "ciphertexts": [hex(c) for c in ciphertexts],
        "moduli_hex": [hex(n) for n in moduli],
        "recovered_plaintext": m_recovered,
        "attack_succeeded": success,
        "error": error,
        "note": "Attack requires unpadded (textbook) RSA. PKCS#1 v1.5 prevents it.",
    }


def demo_crt_speedup(bits: int = 512, trials: int = 10) -> dict:
    """Benchmark CRT vs naive RSA decryption."""
    import time
    from src.pa12_rsa.rsa import rsa_keygen, rsa_enc

    pk, sk = rsa_keygen(bits)
    messages = [i + 1 for i in range(trials)]
    ciphertexts = [rsa_enc(pk, m) for m in messages]

    # Naive
    t0 = time.perf_counter()
    naive_results = [rsa_dec(sk, c) for c in ciphertexts]
    t_naive = time.perf_counter() - t0

    # CRT
    t0 = time.perf_counter()
    crt_results = [rsa_dec_crt(sk, c) for c in ciphertexts]
    t_crt = time.perf_counter() - t0

    speedup = t_naive / t_crt if t_crt > 0 else float("inf")
    correct = naive_results == crt_results

    return {
        "bits": bits,
        "trials": trials,
        "naive_time_s": round(t_naive, 4),
        "crt_time_s": round(t_crt, 4),
        "speedup": round(speedup, 2),
        "results_match": correct,
        "expected_speedup": "~3-4x",
    }
