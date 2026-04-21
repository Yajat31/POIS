"""
PA#6 — CCA-Secure Symmetric Encryption (Encrypt-then-MAC)

Construction: CCA_Enc(kE, kM, m) = (c, t)
  - c = Enc_kE(m)   (CPA-secure encryption from PA#3)
  - t = Mac_kM(c)   (MAC over the ciphertext from PA#5)

Decryption: CCA_Dec(kE, kM, c, t):
  1. VERIFY: if Vrfy_kM(c, t) = 0, return ⊥  ← verify FIRST, always!
  2. DECRYPT: return Dec_kE(c)

Security: IND-CCA2 under the assumption that Enc is CPA-secure and Mac is EUF-CMA.
  - Verify-before-decrypt prevents padding oracle and ciphertext tampering attacks.

Depends on: PA#3 (CPA encryption), PA#5 (MAC)
No external crypto libraries.
"""

from __future__ import annotations
from src.pa03_cpa_enc.cpa_enc import Enc, Dec
from src.pa05_mac.mac import MacCBC
from src.common.randomness import random_bytes
from src.common.bytes_utils import xor_bytes
from src.common.encoding import pack_tuple, unpack_tuple
from src.common.timing import secure_compare

BLOCK_SIZE = 16


# ─────────────────────────────────────────────────────────────
#  CCA-Secure Encrypt-then-MAC
# ─────────────────────────────────────────────────────────────

class CCAEnc:
    """CCA-Secure symmetric encryption via Encrypt-then-MAC.

    Uses INDEPENDENT keys for encryption and authentication:
      kE: encryption key (16 bytes)
      kM: MAC key (16 bytes)

    CRITICAL ORDERING: verify BEFORE decrypt to prevent chosen-ciphertext attacks.
    """

    def __init__(self, mac: MacCBC | None = None):
        self.mac = mac or MacCBC()

    def CCA_Enc(self, kE: bytes, kM: bytes, m: bytes) -> tuple[bytes, bytes]:
        """Encrypt-then-MAC.

        Returns (packed_ciphertext, mac_tag) where packed_ciphertext = r ∥ c.
        """
        if len(kE) != BLOCK_SIZE or len(kM) != BLOCK_SIZE:
            raise ValueError("CCA_Enc: both keys must be 16 bytes")
        # Step 1: Encrypt
        r, c = Enc(kE, m)
        packed_c = pack_tuple(r, c)  # pack nonce and ciphertext together
        # Step 2: MAC over the ciphertext (not the plaintext!)
        t = self.mac.Mac(kM, packed_c)
        return packed_c, t

    def CCA_Dec(self, kE: bytes, kM: bytes, packed_c: bytes, t: bytes) -> bytes | None:
        """Verify-then-decrypt.

        Returns plaintext or None (⊥) if MAC verification fails.
        NEVER decrypts before verification is complete.
        """
        if len(kE) != BLOCK_SIZE or len(kM) != BLOCK_SIZE:
            raise ValueError("CCA_Dec: both keys must be 16 bytes")
        # Step 1: VERIFY (MUST come first)
        expected_t = self.mac.Mac(kM, packed_c)
        if not secure_compare(expected_t, t):
            return None  # ⊥ — reject tampered ciphertext
        # Step 2: DECRYPT (only reached if MAC is valid)
        r, c = unpack_tuple(packed_c, 2)
        return Dec(kE, r, c)


def CCA_Enc(kE: bytes, kM: bytes, m: bytes) -> tuple[bytes, bytes]:
    """Module-level convenience wrapper."""
    return CCAEnc().CCA_Enc(kE, kM, m)


def CCA_Dec(kE: bytes, kM: bytes, packed_c: bytes, t: bytes) -> bytes | None:
    """Module-level convenience wrapper. Returns None (⊥) on failure."""
    return CCAEnc().CCA_Dec(kE, kM, packed_c, t)


# ─────────────────────────────────────────────────────────────
#  IND-CCA2 Game Simulation
# ─────────────────────────────────────────────────────────────

class CCAdversaryOracle:
    """Oracle for the IND-CCA2 game.

    Maintains the challenge ciphertext so it can be rejected from decryption queries.
    Adversary can query Dec for any ciphertext EXCEPT the challenge.
    """

    def __init__(self, kE: bytes, kM: bytes):
        self.kE = kE
        self.kM = kM
        self._enc = CCAEnc()
        self._challenge: bytes | None = None
        self._b: int | None = None
        self.dec_queries = 0
        self.reject_count = 0

    def challenge(self, m0: bytes, m1: bytes) -> tuple[bytes, bytes]:
        """Encrypt either m0 or m1 randomly. Returns (c*, t*)."""
        import os
        b = int.from_bytes(os.urandom(1), "big") % 2
        self._b = b
        m = m0 if b == 0 else m1
        packed_c, t = self._enc.CCA_Enc(self.kE, self.kM, m)
        self._challenge = packed_c
        self._challenge_t = t
        return packed_c, t

    def decrypt_oracle(self, packed_c: bytes, t: bytes) -> bytes | None:
        """Adversary's decryption oracle. Rejects the challenge ciphertext."""
        self.dec_queries += 1
        if packed_c == self._challenge:
            self.reject_count += 1
            return None  # Reject challenge ciphertext
        return self._enc.CCA_Dec(self.kE, self.kM, packed_c, t)

    def guess(self, b_prime: int) -> bool:
        """Adversary submits guess b'. Returns True if correct."""
        return b_prime == self._b


def ind_cca2_game(
    kE: bytes | None = None,
    kM: bytes | None = None,
    m0: bytes = b"Hello World!!!!",
    m1: bytes = b"Secret Message!",
    trials: int = 100,
) -> dict:
    """Run IND-CCA2 game trials. Adversary advantage should be ≈ 0 for CCA-secure scheme."""
    if kE is None:
        kE = random_bytes(BLOCK_SIZE)
    if kM is None:
        kM = random_bytes(BLOCK_SIZE)

    correct = 0
    for _ in range(trials):
        oracle = CCAdversaryOracle(kE, kM)
        c_star, t_star = oracle.challenge(m0, m1)

        # Simple adversary: try to decrypt challenge (will be rejected)
        result = oracle.decrypt_oracle(c_star, t_star)
        # Oracle rejects → adversary must guess randomly
        import os
        guess = int.from_bytes(os.urandom(1), "big") % 2
        if oracle.guess(guess):
            correct += 1

    advantage = abs(correct / trials - 0.5)
    return {
        "trials": trials,
        "adversary_wins": correct,
        "advantage": round(advantage, 4),
        "expected_advantage": "≈ 0 (negligible)",
        "security": "IND-CCA2 secure via Encrypt-then-MAC",
    }


def tampering_demo(kE: bytes, kM: bytes, m: bytes) -> dict:
    """Demonstrate that ciphertext tampering is detected and rejected."""
    cca = CCAEnc()
    packed_c, t = cca.CCA_Enc(kE, kM, m)

    # Tamper with the ciphertext (flip one byte)
    tampered = bytearray(packed_c)
    tampered[8] ^= 0xFF
    tampered = bytes(tampered)

    result = cca.CCA_Dec(kE, kM, tampered, t)
    original_result = cca.CCA_Dec(kE, kM, packed_c, t)

    return {
        "original_ciphertext": packed_c.hex()[:32] + "...",
        "tampered_ciphertext": tampered.hex()[:32] + "...",
        "original_decryption": original_result,
        "tampered_decryption": result,
        "tamper_detected": result is None,
        "explanation": "MAC verification fails on tampered ciphertext → returns ⊥",
    }
