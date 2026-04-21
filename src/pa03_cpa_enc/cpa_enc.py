"""
PA#3 — CPA-Secure Symmetric Encryption

Construction: Enc(k, m) = ⟨r, F_k(r) ⊕ m⟩
  - r: fresh random nonce (16 bytes)
  - F_k: PRF from PA#2 (AES-based by default)
  - m: message (padded to block size if needed)

Multi-block: for message m = m_1 ∥ ... ∥ m_t,
  Enc(k, m) = ⟨r, F_k(r) ⊕ m_1, F_k(r+1) ⊕ m_2, ..., F_k(r+t-1) ⊕ m_t⟩
  where r+i is the counter (big-endian increment).

Security: IND-CPA under PRF assumption.
WARNING: Nonce reuse breaks security catastrophically.

Depends on: PA#2 (PRFFromAES)
No external crypto libraries.
"""

from __future__ import annotations
from src.pa02_prf.ggm_prf import PRFFromAES
from src.common.randomness import random_bytes
from src.common.bytes_utils import xor_bytes, int_to_bytes, bytes_to_int
from src.common.padding import pkcs7_pad, pkcs7_unpad
from src.common.encoding import pack_tuple, unpack_tuple


BLOCK_SIZE = 16  # AES block size in bytes


def _increment_counter(r: bytes) -> bytes:
    """Increment a 16-byte counter (big-endian) by 1."""
    n = bytes_to_int(r)
    return int_to_bytes((n + 1) % (2**128), 16)


def Enc(k: bytes, m: bytes, prf: PRFFromAES | None = None) -> tuple[bytes, bytes]:
    """CPA-secure encryption.

    Args:
        k: 16-byte key
        m: plaintext (arbitrary length)
        prf: PRF instance (default: PRFFromAES)

    Returns:
        (r, c) where r is the random nonce (16 bytes) and c is the ciphertext.
    """
    if prf is None:
        prf = PRFFromAES()
    r = random_bytes(BLOCK_SIZE)  # fresh random nonce every call!
    # Pad message to multiple of block size
    padded = pkcs7_pad(m, BLOCK_SIZE)
    # Encrypt block by block with counter
    ciphertext = b""
    counter = r
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i : i + BLOCK_SIZE]
        keystream = prf.F(k, counter)
        ciphertext += xor_bytes(block, keystream)
        counter = _increment_counter(counter)
    return r, ciphertext


def Dec(k: bytes, r: bytes, c: bytes, prf: PRFFromAES | None = None) -> bytes:
    """CPA-secure decryption.

    Args:
        k: 16-byte key
        r: nonce (16 bytes) as returned by Enc
        c: ciphertext

    Returns:
        plaintext bytes
    """
    if prf is None:
        prf = PRFFromAES()
    if len(c) % BLOCK_SIZE != 0:
        raise ValueError("Dec: ciphertext length must be a multiple of 16")
    plaintext_padded = b""
    counter = r
    for i in range(0, len(c), BLOCK_SIZE):
        block = c[i : i + BLOCK_SIZE]
        keystream = prf.F(k, counter)
        plaintext_padded += xor_bytes(block, keystream)
        counter = _increment_counter(counter)
    return pkcs7_unpad(plaintext_padded)


def enc_pack(k: bytes, m: bytes, prf: PRFFromAES | None = None) -> bytes:
    """Encrypt and pack (r ∥ c) into a single bytes object."""
    r, c = Enc(k, m, prf)
    return pack_tuple(r, c)


def dec_unpack(k: bytes, packed: bytes, prf: PRFFromAES | None = None) -> bytes:
    """Unpack and decrypt a packed ciphertext."""
    r, c = unpack_tuple(packed, 2)
    return Dec(k, r, c, prf)


# ─────────────────────────────────────────────────────────────
#  Broken Deterministic Variant (for demo — INSECURE)
# ─────────────────────────────────────────────────────────────

_FIXED_NONCE = b"\x00" * BLOCK_SIZE


def broken_enc(k: bytes, m: bytes, prf: PRFFromAES | None = None) -> tuple[bytes, bytes]:
    """INSECURE deterministic encryption: always uses r = 0^128.

    This is CPA-INSECURE: same plaintext always gives same ciphertext.
    Kept separate and labelled as insecure per PDF spec.
    """
    if prf is None:
        prf = PRFFromAES()
    r = _FIXED_NONCE
    padded = pkcs7_pad(m, BLOCK_SIZE)
    ciphertext = b""
    counter = r
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i : i + BLOCK_SIZE]
        keystream = prf.F(k, counter)
        ciphertext += xor_bytes(block, keystream)
        counter = _increment_counter(counter)
    return r, ciphertext


# ─────────────────────────────────────────────────────────────
#  IND-CPA Game Simulation
# ─────────────────────────────────────────────────────────────

def ind_cpa_game(
    k: bytes,
    m0: bytes,
    m1: bytes,
    prf: PRFFromAES | None = None,
    use_broken: bool = False,
) -> dict:
    """Simulate one round of the IND-CPA security game.

    Challenger encrypts either m0 or m1 (chosen randomly).
    Adversary sees the ciphertext and must guess which was encrypted.
    For the secure scheme, advantage ≈ 0. For broken scheme, advantage = 1.

    Args:
        k: secret key
        m0, m1: two equal-length challenge messages
        use_broken: if True, uses the deterministic broken variant

    Returns:
        dict with experiment details and adversary advantage estimate.
    """
    import os
    if len(m0) != len(m1):
        raise ValueError("IND-CPA game requires equal-length messages")

    b = int.from_bytes(os.urandom(1), "big") % 2
    chosen = m0 if b == 0 else m1

    if use_broken:
        r, c = broken_enc(k, chosen, prf)
        # Trivial distinguisher: encrypt m0 with same nonce and compare
        r0, c0 = broken_enc(k, m0, prf)
        adv_guess = 0 if c == c0 else 1
    else:
        r, c = Enc(k, chosen, prf)
        # Best adversary can do: random guess
        adv_guess = int.from_bytes(os.urandom(1), "big") % 2

    correct = adv_guess == b
    return {
        "b": b,
        "adversary_guess": adv_guess,
        "correct": correct,
        "ciphertext_hex": c.hex(),
        "nonce_hex": r.hex(),
        "scheme": "BROKEN (deterministic)" if use_broken else "SECURE (randomized)",
    }


def ind_cpa_advantage(
    k: bytes,
    m0: bytes,
    m1: bytes,
    trials: int = 200,
    prf: PRFFromAES | None = None,
) -> dict:
    """Run IND-CPA game *trials* times and report adversary advantage.

    Returns dict with advantage for both secure and broken schemes.
    """
    def run_trial(broken: bool) -> bool:
        result = ind_cpa_game(k, m0, m1, prf, use_broken=broken)
        return result["correct"]

    secure_wins = sum(run_trial(False) for _ in range(trials))
    broken_wins = sum(run_trial(True) for _ in range(trials))

    return {
        "trials": trials,
        "secure_scheme": {
            "wins": secure_wins,
            "advantage": round(abs(secure_wins / trials - 0.5), 4),
            "expected": "~0 (negligible)",
        },
        "broken_scheme": {
            "wins": broken_wins,
            "advantage": round(abs(broken_wins / trials - 0.5), 4),
            "expected": "~0.5 (trivially distinguishable)",
        },
    }
