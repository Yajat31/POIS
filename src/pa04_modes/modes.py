"""
PA#4 — Block Cipher Modes of Operation: CBC, OFB, CTR

Implements:
  - CBC_Enc / CBC_Dec  (Cipher Block Chaining)
  - OFB_Enc / OFB_Dec  (Output Feedback Mode)
  - CTR_Enc / CTR_Dec  (Counter Mode — randomized)
  - Encrypt / Decrypt  (unified router)

Security requirements:
  - CBC: random IV per message
  - OFB: unique IV per (key, message) pair — reuse leaks XOR of plaintexts
  - CTR: fresh random nonce per message — reuse is catastrophic

Attack demos:
  - CBC IV-reuse leakage
  - OFB keystream reuse → plaintext XOR recovery
  - Bit-flip error propagation

Depends on: src/foundations/aes_impl.py (AES-128)
No external crypto libraries.
"""

from __future__ import annotations
from src.foundations.aes_impl import aes_encrypt_block, aes_decrypt_block
from src.common.randomness import random_bytes
from src.common.bytes_utils import xor_bytes, int_to_bytes, bytes_to_int
from src.common.padding import pkcs7_pad, pkcs7_unpad

BLOCK_SIZE = 16  # AES block size


def _inc_counter(c: bytes) -> bytes:
    """Increment a 16-byte counter block (big-endian)."""
    n = bytes_to_int(c)
    return int_to_bytes((n + 1) % (2 ** 128), BLOCK_SIZE)


# ─────────────────────────────────────────────────────────────
#  CBC Mode
# ─────────────────────────────────────────────────────────────

def CBC_Enc(k: bytes, iv: bytes, M: bytes) -> bytes:
    """Encrypt plaintext M using CBC mode.

    Returns the ciphertext (without IV prepended — caller tracks IV separately).
    M is PKCS#7-padded internally.
    """
    if len(k) != BLOCK_SIZE or len(iv) != BLOCK_SIZE:
        raise ValueError("CBC_Enc: key and IV must be 16 bytes each")
    padded = pkcs7_pad(M, BLOCK_SIZE)
    C = b""
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i : i + BLOCK_SIZE]
        ct_block = aes_encrypt_block(k, xor_bytes(block, prev))
        C += ct_block
        prev = ct_block
    return C


def CBC_Dec(k: bytes, iv: bytes, C: bytes) -> bytes:
    """Decrypt CBC ciphertext C. Returns unpadded plaintext."""
    if len(k) != BLOCK_SIZE or len(iv) != BLOCK_SIZE:
        raise ValueError("CBC_Dec: key and IV must be 16 bytes each")
    if len(C) % BLOCK_SIZE != 0:
        raise ValueError("CBC_Dec: ciphertext length must be a multiple of 16")
    plaintext_padded = b""
    prev = iv
    for i in range(0, len(C), BLOCK_SIZE):
        ct_block = C[i : i + BLOCK_SIZE]
        pt_block = xor_bytes(aes_decrypt_block(k, ct_block), prev)
        plaintext_padded += pt_block
        prev = ct_block
    return pkcs7_unpad(plaintext_padded)


# ─────────────────────────────────────────────────────────────
#  OFB Mode
# ─────────────────────────────────────────────────────────────

def _ofb_keystream(k: bytes, iv: bytes, length: int) -> bytes:
    """Generate *length* bytes of OFB keystream starting from iv."""
    ks = b""
    state = iv
    while len(ks) < length:
        state = aes_encrypt_block(k, state)
        ks += state
    return ks[:length]


def OFB_Enc(k: bytes, iv: bytes, M: bytes) -> bytes:
    """Encrypt plaintext M using OFB mode. Returns ciphertext (same length as M)."""
    if len(k) != BLOCK_SIZE or len(iv) != BLOCK_SIZE:
        raise ValueError("OFB_Enc: key and IV must be 16 bytes each")
    ks = _ofb_keystream(k, iv, len(M))
    return bytes(a ^ b for a, b in zip(M, ks))


def OFB_Dec(k: bytes, iv: bytes, C: bytes) -> bytes:
    """Decrypt OFB ciphertext C. OFB is symmetric: Dec = Enc."""
    return OFB_Enc(k, iv, C)


# ─────────────────────────────────────────────────────────────
#  CTR Mode (randomized)
# ─────────────────────────────────────────────────────────────

def CTR_Enc(k: bytes, M: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext M using randomized CTR mode.

    Returns (r, C) where r is the random 16-byte nonce/counter start.
    Parallelizable: block i uses counter r+i independently.
    """
    if len(k) != BLOCK_SIZE:
        raise ValueError("CTR_Enc: key must be 16 bytes")
    r = random_bytes(BLOCK_SIZE)
    C = b""
    counter = r
    for i in range(0, len(M), BLOCK_SIZE):
        block = M[i : i + BLOCK_SIZE]
        ks_block = aes_encrypt_block(k, counter)
        C += bytes(a ^ b for a, b in zip(block, ks_block))
        counter = _inc_counter(counter)
    return r, C


def CTR_Dec(k: bytes, r: bytes, C: bytes) -> bytes:
    """Decrypt CTR ciphertext. CTR is symmetric."""
    if len(k) != BLOCK_SIZE or len(r) != BLOCK_SIZE:
        raise ValueError("CTR_Dec: key and nonce must be 16 bytes each")
    M = b""
    counter = r
    for i in range(0, len(C), BLOCK_SIZE):
        block = C[i : i + BLOCK_SIZE]
        ks_block = aes_encrypt_block(k, counter)
        M += bytes(a ^ b for a, b in zip(block, ks_block))
        counter = _inc_counter(counter)
    return M


def CTR_Enc_parallel(k: bytes, M: bytes) -> tuple[bytes, bytes]:
    """Parallelizable CTR encryption demonstration.

    Each block is independently computed: C_i = AES_k(r+i) ⊕ M_i.
    Returns (r, C). In Python we simulate parallel blocks conceptually.
    """
    r = random_bytes(BLOCK_SIZE)
    num_blocks = (len(M) + BLOCK_SIZE - 1) // BLOCK_SIZE
    # Generate all counter blocks
    counters = []
    c = r
    for _ in range(num_blocks):
        counters.append(c)
        c = _inc_counter(c)
    # Encrypt each block independently (parallelizable)
    C_blocks = [
        bytes(a ^ b for a, b in zip(
            M[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE],
            aes_encrypt_block(k, counters[i])
        ))
        for i in range(num_blocks)
    ]
    return r, b"".join(C_blocks)


# ─────────────────────────────────────────────────────────────
#  Unified Router
# ─────────────────────────────────────────────────────────────

SUPPORTED_MODES = {"CBC", "OFB", "CTR"}


def Encrypt(mode: str, k: bytes, M: bytes, iv: bytes | None = None) -> dict:
    """Unified encryption router.

    Args:
        mode: "CBC", "OFB", or "CTR"
        k: 16-byte key
        M: plaintext
        iv: IV for CBC/OFB (auto-generated if None); ignored for CTR

    Returns dict with ciphertext and parameters.
    """
    mode = mode.upper()
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"Unknown mode: {mode}. Supported: {SUPPORTED_MODES}")

    if mode == "CBC":
        iv = iv or random_bytes(BLOCK_SIZE)
        C = CBC_Enc(k, iv, M)
        return {"mode": "CBC", "iv": iv, "ciphertext": C}
    elif mode == "OFB":
        iv = iv or random_bytes(BLOCK_SIZE)
        C = OFB_Enc(k, iv, M)
        return {"mode": "OFB", "iv": iv, "ciphertext": C}
    elif mode == "CTR":
        r, C = CTR_Enc(k, M)
        return {"mode": "CTR", "nonce": r, "ciphertext": C}


def Decrypt(mode: str, k: bytes, C: bytes, iv: bytes | None = None, nonce: bytes | None = None) -> bytes:
    """Unified decryption router."""
    mode = mode.upper()
    if mode == "CBC":
        return CBC_Dec(k, iv, C)
    elif mode == "OFB":
        return OFB_Dec(k, iv, C)
    elif mode == "CTR":
        return CTR_Dec(k, nonce, C)
    else:
        raise ValueError(f"Unknown mode: {mode}")


# ─────────────────────────────────────────────────────────────
#  Attack Demos
# ─────────────────────────────────────────────────────────────

def attack_cbc_iv_reuse(k: bytes, iv: bytes, m1: bytes, m2: bytes) -> dict:
    """CBC IV-reuse attack demo.

    If two messages are encrypted with the same (k, IV):
      C1_0 = AES_k(IV ⊕ m1_0)
      C2_0 = AES_k(IV ⊕ m2_0)
    An attacker who knows m1_0 can check if the first blocks match,
    immediately leaking whether m2_0 == m1_0.
    """
    m1_padded = pkcs7_pad(m1, BLOCK_SIZE)
    m2_padded = pkcs7_pad(m2, BLOCK_SIZE)
    C1 = CBC_Enc(k, iv, m1)
    C2 = CBC_Enc(k, iv, m2)

    # If C1[:16] == C2[:16] then m1[:16] == m2[:16]
    first_blocks_match = C1[:BLOCK_SIZE] == C2[:BLOCK_SIZE]
    return {
        "attack": "CBC IV-reuse",
        "c1_first_block": C1[:BLOCK_SIZE].hex(),
        "c2_first_block": C2[:BLOCK_SIZE].hex(),
        "blocks_match": first_blocks_match,
        "m1_first_block_matches_m2": m1[:BLOCK_SIZE] == m2[:BLOCK_SIZE],
        "leak": "If C1[0] == C2[0] then M1[0] XOR IV == M2[0] XOR IV → M1[0] == M2[0]",
    }


def attack_ofb_keystream_reuse(k: bytes, iv: bytes, m1: bytes, m2: bytes) -> dict:
    """OFB keystream reuse attack.

    If OFB keystream is reused (same k, same IV):
      C1 = M1 ⊕ KS
      C2 = M2 ⊕ KS
    Then C1 ⊕ C2 = M1 ⊕ M2 — the XOR of plaintexts is directly revealed.
    """
    min_len = min(len(m1), len(m2))
    C1 = OFB_Enc(k, iv, m1[:min_len])
    C2 = OFB_Enc(k, iv, m2[:min_len])

    # Recovered: M1 ⊕ M2
    xor_plaintexts = bytes(a ^ b for a, b in zip(m1[:min_len], m2[:min_len]))
    recovered = bytes(a ^ b for a, b in zip(C1, C2))

    return {
        "attack": "OFB keystream reuse",
        "c1_xor_c2": recovered.hex(),
        "m1_xor_m2": xor_plaintexts.hex(),
        "attack_succeeds": recovered == xor_plaintexts,
        "leak": "C1 ⊕ C2 = M1 ⊕ M2 directly reveals XOR of plaintexts",
    }


def attack_bitflip_propagation(k: bytes, flip_byte: int = 0, flip_bit: int = 0) -> dict:
    """Demonstrate bit-flip error propagation in CBC, OFB, CTR.

    In CBC: flipping bit i in C_j garbles block j+1 entirely (16 bytes affected)
             and flips the corresponding bit in block j+2 (1 bit affected).
    In OFB: flipping bit i in C_j flips exactly bit i in the recovered M_j (1 bit).
    In CTR: flipping bit i in C_j flips exactly bit i in the recovered M_j (1 bit).
    """
    M = b"AAAAAAAAAAAAAAAA" + b"BBBBBBBBBBBBBBBB" + b"CCCCCCCCCCCCCCCC"
    iv = b"\x00" * BLOCK_SIZE
    key = random_bytes(BLOCK_SIZE)

    results = {}

    for mode in ["CBC", "OFB", "CTR"]:
        result = Encrypt(mode, key, M, iv=iv if mode != "CTR" else None)
        C = result["ciphertext"]

        # Flip one bit in the first block of ciphertext
        C_list = bytearray(C)
        if flip_byte < len(C_list):
            C_list[flip_byte] ^= (1 << flip_bit)
        C_flipped = bytes(C_list)

        # Attempt decryption
        try:
            if mode == "CBC":
                M_dec = CBC_Dec(key, iv, C_flipped)
            elif mode == "OFB":
                M_dec = OFB_Dec(key, iv, C_flipped)
            elif mode == "CTR":
                M_dec = CTR_Dec(key, result["nonce"], C_flipped)
        except Exception as e:
            M_dec = b"<decryption error>"

        # Count differing bytes
        diffs = sum(1 for a, b in zip(M, M_dec) if a != b)
        results[mode] = {
            "original": M.hex(),
            "decrypted_after_flip": M_dec.hex(),
            "differing_bytes": diffs,
        }

    results["analysis"] = {
        "CBC": "Flipping bit in C_j garbles ~16 bytes in block j AND flips 1 bit in block j+1",
        "OFB": "Flipping bit in C_j flips exactly 1 bit in M_j (stream cipher property)",
        "CTR": "Flipping bit in C_j flips exactly 1 bit in M_j (stream cipher property)",
    }
    return results
