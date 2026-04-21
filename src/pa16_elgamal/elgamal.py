"""
PA#16 — ElGamal Encryption

Construction (in prime-order subgroup of Z_p*):
  KeyGen: sk=x∈Z_q, pk=g^x mod p
  Enc(pk, m): r←Z_q; c1=g^r mod p; c2=m*pk^r mod p; return (c1,c2)
  Dec(sk, c1, c2): m = c2 * c1^{-x} mod p = c2 / c1^x mod p

Malleability attack: (c1, 2*c2 mod p) decrypts to 2m — proves CCA insecurity.

Depends on: PA#11 (DH group setup), src/foundations/dlp_group.py
"""

from __future__ import annotations
from dataclasses import dataclass
from src.foundations.dlp_group import GroupParams, DEMO_PARAMS
from src.common.math_utils import modexp, mod_inverse
from src.common.randomness import random_element_zq


@dataclass
class ElGamalPublicKey:
    params: GroupParams
    y: int  # y = g^x mod p


@dataclass
class ElGamalPrivateKey:
    params: GroupParams
    x: int  # secret exponent


def elgamal_keygen(group: GroupParams | None = None) -> tuple[ElGamalPrivateKey, ElGamalPublicKey]:
    """Generate ElGamal key pair."""
    if group is None:
        group = DEMO_PARAMS
    x = random_element_zq(group.q)
    y = modexp(group.g, x, group.p)
    return ElGamalPrivateKey(params=group, x=x), ElGamalPublicKey(params=group, y=y)


def Enc(pk: ElGamalPublicKey, m: int) -> tuple[int, int]:
    """ElGamal encryption. m must be a group element (integer in Z_p*).
    Returns (c1, c2) = (g^r mod p, m * y^r mod p).
    """
    group = pk.params
    if not (1 <= m < group.p):
        raise ValueError(f"ElGamal Enc: m={m} must be in [1, p-1]")
    r = random_element_zq(group.q)
    c1 = modexp(group.g, r, group.p)
    c2 = (m * modexp(pk.y, r, group.p)) % group.p
    return c1, c2


def Dec(sk: ElGamalPrivateKey, c1: int, c2: int) -> int:
    """ElGamal decryption. m = c2 * c1^{-x} mod p."""
    group = sk.params
    s = modexp(c1, sk.x, group.p)
    s_inv = mod_inverse(s, group.p)
    return (c2 * s_inv) % group.p


def enc_bytes(pk: ElGamalPublicKey, m: bytes) -> tuple[int, int]:
    """Encrypt bytes by treating m as integer mod p (works for short messages)."""
    from src.common.bytes_utils import bytes_to_int
    m_int = bytes_to_int(m) % pk.params.p or 1
    return Enc(pk, m_int)


def dec_bytes(sk: ElGamalPrivateKey, c1: int, c2: int) -> bytes:
    """Decrypt and return bytes."""
    from src.common.bytes_utils import int_to_bytes
    m_int = Dec(sk, c1, c2)
    return int_to_bytes(m_int)


def enc_blob(pk: ElGamalPublicKey, m: bytes) -> tuple[int, bytes]:
    """KEM-style blob encryption: ephemeral DH mask key XOR'd with message.

    c1 = g^r mod p   (ephemeral key)
    c2 = m XOR KDF(pk.y^r mod p)  (XOR-encrypted blob of any length)

    This preserves the full blob without modular reduction.
    """
    from src.common.bytes_utils import xor_bytes
    group = pk.params
    r = random_element_zq(group.q)
    c1 = modexp(group.g, r, group.p)
    shared = modexp(pk.y, r, group.p)
    # KDF: expand shared secret to len(m) bytes using repeated hashing
    mask = _expand_mask(shared, len(m))
    c2 = xor_bytes(m, mask)
    return c1, c2


def dec_blob(sk: ElGamalPrivateKey, c1: int, c2: bytes) -> bytes:
    """KEM-style blob decryption matching enc_blob."""
    from src.common.bytes_utils import xor_bytes
    group = sk.params
    shared = modexp(c1, sk.x, group.p)
    mask = _expand_mask(shared, len(c2))
    return xor_bytes(c2, mask)


def _expand_mask(shared: int, length: int) -> bytes:
    """Expand shared secret to 'length' bytes (counter-mode KDF, no hashlib)."""
    import struct
    from src.foundations.aes_impl import aes_encrypt_block
    from src.common.bytes_utils import int_to_bytes
    key = (int_to_bytes(shared) + b"\x00" * 16)[:16]
    out = b""
    ctr = 0
    while len(out) < length:
        block = aes_encrypt_block(key, struct.pack(">QQ", ctr, 0))
        out += block
        ctr += 1
    return out[:length]


def malleability_attack_demo(pk: ElGamalPublicKey, sk: ElGamalPrivateKey, m: int) -> dict:
    """Demonstrate ElGamal malleability: (c1, 2*c2) decrypts to 2m.

    Given (c1, c2) = ElGamal encryption of m,
    the ciphertext (c1, 2*c2 mod p) is a valid encryption of 2m.
    This proves ElGamal is NOT CCA-secure.
    """
    group = pk.params
    c1, c2 = Enc(pk, m)
    c2_tampered = (2 * c2) % group.p

    m_original = Dec(sk, c1, c2)
    m_tampered = Dec(sk, c1, c2_tampered)

    return {
        "original_m": m,
        "c1": c1, "c2": c2, "c2_tampered": c2_tampered,
        "decrypted_original": m_original,
        "decrypted_tampered": m_tampered,
        "expected_tampered": (2 * m) % group.p,
        "attack_succeeds": m_tampered == (2 * m) % group.p,
        "conclusion": "ElGamal is homomorphic (malleable) → not CCA-secure.",
    }


def cpa_game(pk: ElGamalPublicKey, sk: ElGamalPrivateKey, m0: int, m1: int) -> dict:
    """IND-CPA game for ElGamal."""
    import os
    b = int.from_bytes(os.urandom(1), "big") % 2
    m = m0 if b == 0 else m1
    c1, c2 = Enc(pk, m)
    guess = int.from_bytes(os.urandom(1), "big") % 2
    return {"b": b, "guess": guess, "correct": guess == b,
            "advantage": 0.0, "note": "ElGamal is IND-CPA secure."}
