"""
PA#12 — RSA: Textbook and PKCS#1 v1.5

Depends on: PA#13 (gen_prime), src/common/math_utils.py, src/common/padding.py
No external crypto libraries.
"""

from __future__ import annotations
from dataclasses import dataclass
from src.pa13_miller_rabin.miller_rabin import gen_prime
from src.common.math_utils import modexp, mod_inverse, lcm
from src.common.randomness import random_bytes
from src.common.bytes_utils import bytes_to_int, int_to_bytes
from src.common.padding import pkcs1_v15_pad, pkcs1_v15_unpad


@dataclass
class RSAPublicKey:
    n: int
    e: int


@dataclass
class RSAPrivateKey:
    n: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    q_inv: int


def rsa_keygen(bits: int = 512, e: int = 65537) -> tuple[RSAPublicKey, RSAPrivateKey]:
    """Generate RSA key pair using own PA#13 primality testing."""
    half_bits = bits // 2
    while True:
        p = gen_prime(half_bits)
        q = gen_prime(half_bits)
        if p == q:
            continue
        n = p * q
        lambda_n = lcm(p - 1, q - 1)
        if lambda_n % e == 0:
            continue
        try:
            d = mod_inverse(e, lambda_n)
        except ValueError:
            continue
        break
    dp = d % (p - 1)
    dq = d % (q - 1)
    q_inv = mod_inverse(q, p)
    return RSAPublicKey(n=n, e=e), RSAPrivateKey(n=n, d=d, p=p, q=q, dp=dp, dq=dq, q_inv=q_inv)


def rsa_enc(pk: RSAPublicKey, m: int) -> int:
    """Textbook RSA: c = m^e mod n. DETERMINISTIC — NOT CPA secure."""
    if not (0 <= m < pk.n):
        raise ValueError(f"rsa_enc: m={m} out of range")
    return modexp(m, pk.e, pk.n)


def rsa_dec(sk: RSAPrivateKey, c: int) -> int:
    """Textbook RSA decryption: m = c^d mod n."""
    return modexp(c, sk.d, sk.n)


def rsa_enc_bytes(pk: RSAPublicKey, m: bytes) -> bytes:
    n_bytes = (pk.n.bit_length() + 7) // 8
    return int_to_bytes(rsa_enc(pk, bytes_to_int(m)), n_bytes)


def rsa_dec_bytes(sk: RSAPrivateKey, c: bytes) -> bytes:
    return int_to_bytes(rsa_dec(sk, bytes_to_int(c)))


def pkcs15_enc(pk: RSAPublicKey, m: bytes) -> bytes:
    """PKCS#1 v1.5 randomized encryption."""
    n_bytes = (pk.n.bit_length() + 7) // 8
    padded = pkcs1_v15_pad(m, n_bytes)
    c_int = modexp(bytes_to_int(padded), pk.e, pk.n)
    return int_to_bytes(c_int, n_bytes)


def pkcs15_dec(sk: RSAPrivateKey, c: bytes) -> bytes | None:
    """PKCS#1 v1.5 decryption. Returns None (⊥) on malformed padding."""
    n_bytes = (sk.n.bit_length() + 7) // 8
    padded_int = modexp(bytes_to_int(c), sk.d, sk.n)
    padded = int_to_bytes(padded_int, n_bytes)
    try:
        return pkcs1_v15_unpad(padded)
    except ValueError:
        return None


def pkcs15_oracle(sk: RSAPrivateKey, c: bytes) -> bool:
    """PKCS#1 v1.5 padding oracle: True if padding is valid."""
    return pkcs15_dec(sk, c) is not None


def demo_textbook_rsa_determinism(pk: RSAPublicKey) -> dict:
    m = 42
    c1, c2 = rsa_enc(pk, m), rsa_enc(pk, m)
    return {"plaintext": m, "c1": c1, "c2": c2, "identical": c1 == c2,
            "conclusion": "Textbook RSA: same plaintext → same ciphertext (NOT IND-CPA)."}


def demo_pkcs15_randomization(pk: RSAPublicKey, m: bytes = b"Hello") -> dict:
    c1, c2 = pkcs15_enc(pk, m), pkcs15_enc(pk, m)
    return {"plaintext": m.hex(), "c1": c1.hex(), "c2": c2.hex(), "identical": c1 == c2,
            "conclusion": "PKCS#1 v1.5: random PS → different ciphertext each time."}


def bleichenbacher_toy(pk: RSAPublicKey, sk: RSAPrivateKey, c_bytes: bytes) -> dict:
    """Simplified Bleichenbacher toy attack (only for tiny modulus ≤ 64-bit)."""
    if pk.n.bit_length() > 64:
        return {"note": "Toy attack only for n ≤ 64 bits.", "attack_ran": False}
    n_bytes = (pk.n.bit_length() + 7) // 8
    c = bytes_to_int(c_bytes)
    queries = 0
    for s1 in range(2, min(pk.n, 2000)):
        c_prime = int_to_bytes((c * modexp(s1, pk.e, pk.n)) % pk.n, n_bytes)
        queries += 1
        if pkcs15_oracle(sk, c_prime):
            return {"attack_ran": True, "s1": s1, "oracle_queries": queries,
                    "note": "Found valid blinding factor. Full attack narrows plaintext interval."}
    return {"attack_ran": True, "oracle_queries": queries, "note": "No valid s1 found in range."}
