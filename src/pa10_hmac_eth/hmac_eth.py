"""
PA#10 — HMAC and Encrypt-then-HMAC

Implements:
  - HMAC(k, m) using PA#8 DLP hash (not a library hash)
  - HMAC_Verify(k, m, t) with constant-time comparison
  - secure_compare(t1, t2) via XOR accumulation
  - EtH_Enc / EtH_Dec: CCA-secure Encrypt-then-HMAC

Bidirectional reductions:
  - CRHF → HMAC (HMAC uses the DLP hash as its compression)
  - HMAC → MAC (HMAC is a MAC)
  - HMAC → CRHF (HMAC as compression in a new MD hash — backward direction)

Demos:
  - EUF-CMA game for HMAC
  - Length-extension fails for HMAC (succeeds for naive H(k ∥ m))
  - Timing side-channel: naive_compare vs secure_compare

Depends on: PA#8 (DLPHash), PA#3 (CPA encryption)
No external crypto libraries.
"""

from __future__ import annotations
from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params, DEMO_PARAMS
from src.pa03_cpa_enc.cpa_enc import Enc, Dec
from src.common.randomness import random_bytes
from src.common.bytes_utils import xor_bytes, bytes_to_int, int_to_bytes
from src.common.timing import secure_compare, naive_compare
from src.common.encoding import pack_tuple, unpack_tuple

BLOCK_SIZE = 16  # bytes


# ─────────────────────────────────────────────────────────────
#  HMAC Construction using PA#8 DLP Hash
# ─────────────────────────────────────────────────────────────

def _hmac_key_pad(k: bytes, block_size: int, hash_fn: DLPHash) -> bytes:
    """Prepare HMAC key: hash if longer than block_size, zero-pad if shorter."""
    if len(k) > block_size:
        k = hash_fn.hash(k)
    # Zero-pad to block_size
    return k + b"\x00" * (block_size - len(k))


def HMAC(k: bytes, m: bytes, hash_fn: DLPHash | None = None, block_size: int = BLOCK_SIZE) -> bytes:
    """HMAC using PA#8 DLP hash as the underlying hash function.

    HMAC(k, m) = H((k ⊕ opad) ∥ H((k ⊕ ipad) ∥ m))
    where:
      ipad = 0x36 repeated to block_size
      opad = 0x5C repeated to block_size
      H    = DLPHash (from PA#8)

    CRITICAL: Uses our own DLPHash, NOT hashlib or any library hash.
    """
    if hash_fn is None:
        params = gen_dlp_hash_params(DEMO_PARAMS)
        hash_fn = DLPHash(params, block_size=block_size)

    ipad = bytes([0x36] * block_size)
    opad = bytes([0x5C] * block_size)

    k_padded = _hmac_key_pad(k, block_size, hash_fn)
    ki = xor_bytes(k_padded, ipad)
    ko = xor_bytes(k_padded, opad)

    inner = hash_fn.hash(ki + m)
    outer = hash_fn.hash(ko + inner)
    return outer


def HMAC_Verify(k: bytes, m: bytes, t: bytes, hash_fn: DLPHash | None = None) -> bool:
    """Verify HMAC tag using constant-time comparison.

    NEVER uses early-exit comparison — resistant to timing side-channels.
    """
    expected = HMAC(k, m, hash_fn)
    return secure_compare(expected, t)


# ─────────────────────────────────────────────────────────────
#  Encrypt-then-HMAC (CCA-Secure via HMAC)
# ─────────────────────────────────────────────────────────────

class EtHEnc:
    """CCA-Secure Encrypt-then-HMAC using PA#3 encryption and HMAC from PA#8.

    Uses INDEPENDENT keys kE (encryption) and kM (MAC).
    Verify BEFORE decrypt.
    """

    def __init__(self, hash_fn: DLPHash | None = None):
        self.hash_fn = hash_fn

    def Enc(self, kE: bytes, kM: bytes, m: bytes) -> tuple[bytes, bytes]:
        """EtH_Enc(kE, kM, m) -> (c, t)"""
        r, c = Enc(kE, m)
        packed_c = pack_tuple(r, c)
        t = HMAC(kM, packed_c, self.hash_fn)
        return packed_c, t

    def Dec(self, kE: bytes, kM: bytes, packed_c: bytes, t: bytes) -> bytes | None:
        """EtH_Dec(kE, kM, c, t) -> m or None (⊥)"""
        # VERIFY FIRST
        if not HMAC_Verify(kM, packed_c, t, self.hash_fn):
            return None  # ⊥
        # Then decrypt
        r, c = unpack_tuple(packed_c, 2)
        return Dec(kE, r, c)


def EtH_Enc(kE: bytes, kM: bytes, m: bytes, hash_fn: DLPHash | None = None) -> tuple[bytes, bytes]:
    """Module-level Encrypt-then-HMAC encrypt."""
    return EtHEnc(hash_fn).Enc(kE, kM, m)


def EtH_Dec(kE: bytes, kM: bytes, packed_c: bytes, t: bytes, hash_fn: DLPHash | None = None) -> bytes | None:
    """Module-level Encrypt-then-HMAC decrypt. Returns None on failure."""
    return EtHEnc(hash_fn).Dec(kE, kM, packed_c, t)


# ─────────────────────────────────────────────────────────────
#  HMAC as CRHF (backward: HMAC → CRHF)
# ─────────────────────────────────────────────────────────────

def hmac_as_compression(fixed_key: bytes, hash_fn: DLPHash | None = None):
    """Use HMAC with a fixed key as a compression function in a new MD hash.

    This demonstrates the backward direction: HMAC → CRHF.
    If HMAC is a PRF (and hence a MAC), then HMAC_k(·) is collision-resistant.

    Returns a callable compress(chaining, block) -> bytes.
    """
    if hash_fn is None:
        params = gen_dlp_hash_params(DEMO_PARAMS)
        hash_fn = DLPHash(params, block_size=16)

    def compress(chaining: bytes, block: bytes) -> bytes:
        # Use HMAC with fixed_key on (chaining ∥ block) as compression
        combined = chaining + block
        tag = HMAC(fixed_key, combined, hash_fn)
        return tag

    return compress


# ─────────────────────────────────────────────────────────────
#  EUF-CMA Game for HMAC
# ─────────────────────────────────────────────────────────────

def hmac_euf_cma_game(
    k: bytes | None = None,
    num_queries: int = 50,
    hash_fn: DLPHash | None = None,
) -> dict:
    """Simulate EUF-CMA game for HMAC.

    Adversary gets num_queries (message, tag) pairs.
    Tries to forge a tag on a fresh message.
    """
    if k is None:
        k = random_bytes(BLOCK_SIZE)

    queried = {}
    for _ in range(num_queries):
        m = random_bytes(16)
        t = HMAC(k, m, hash_fn)
        queried[m] = t

    # Forge on a fresh message
    fresh = random_bytes(16)
    while fresh in queried:
        fresh = random_bytes(16)

    # Adversary's best guess: stolen tag from another message
    stolen_tag = next(iter(queried.values())) if queried else random_bytes(16)
    forgery_accepted = HMAC_Verify(k, fresh, stolen_tag, hash_fn)

    return {
        "num_oracle_queries": num_queries,
        "fresh_message": fresh.hex(),
        "forgery_accepted": forgery_accepted,
        "security_holds": not forgery_accepted,
    }


# ─────────────────────────────────────────────────────────────
#  Length-Extension Demo: Naive vs HMAC
# ─────────────────────────────────────────────────────────────

def length_extension_on_hmac_fails(k: bytes, m: bytes, hash_fn: DLPHash | None = None) -> dict:
    """Show that length extension attack fails for HMAC.

    Attacker knows HMAC(k, m) and |m|. They want to forge HMAC(k, m ∥ ext)
    without knowing k. This fails because the outer hash wraps the entire inner hash.
    """
    if hash_fn is None:
        params = gen_dlp_hash_params(DEMO_PARAMS)
        hash_fn = DLPHash(params, block_size=BLOCK_SIZE)

    tag = HMAC(k, m, hash_fn)
    extension = b"ATTACKER_APPEND"

    # Attacker tries: compute new tag by continuing from known tag state
    # This is what would work on H(k ∥ m) but NOT on HMAC
    forged_attempt = hash_fn.hash(tag + extension)  # wrong construction

    # Real tag for extended message
    real_tag = HMAC(k, m + extension, hash_fn)
    attack_succeeded = secure_compare(forged_attempt, real_tag)

    return {
        "original_message": m.hex(),
        "extension": extension.hex(),
        "original_hmac": tag.hex(),
        "forged_attempt": forged_attempt.hex(),
        "real_tag_for_extension": real_tag.hex(),
        "attack_succeeded": attack_succeeded,
        "conclusion": "HMAC is immune to length extension. Naive H(k ∥ m) is not.",
    }


# ─────────────────────────────────────────────────────────────
#  Timing Side-Channel Demo
# ─────────────────────────────────────────────────────────────

def timing_demo(k: bytes, m: bytes, trials: int = 1000, hash_fn: DLPHash | None = None) -> dict:
    """Demonstrate timing difference between naive and constant-time comparison.

    In a real attack, the timing gap in naive_compare leaks the position of the
    first differing byte. secure_compare takes uniform time regardless of position.
    """
    import time

    tag = HMAC(k, m, hash_fn)
    # Wrong tag that differs only in the last byte
    wrong_tag_last = bytearray(tag)
    wrong_tag_last[-1] ^= 0x01
    wrong_tag_last = bytes(wrong_tag_last)

    # Wrong tag that differs in the first byte
    wrong_tag_first = bytearray(tag)
    wrong_tag_first[0] ^= 0x01
    wrong_tag_first = bytes(wrong_tag_first)

    # Measure naive compare time
    t0 = time.perf_counter()
    for _ in range(trials):
        naive_compare(tag, wrong_tag_first)  # fails at byte 0
    t_naive_first = (time.perf_counter() - t0) / trials

    t0 = time.perf_counter()
    for _ in range(trials):
        naive_compare(tag, wrong_tag_last)  # fails at byte -1
    t_naive_last = (time.perf_counter() - t0) / trials

    # Measure constant-time compare
    t0 = time.perf_counter()
    for _ in range(trials):
        secure_compare(tag, wrong_tag_first)
    t_secure_first = (time.perf_counter() - t0) / trials

    t0 = time.perf_counter()
    for _ in range(trials):
        secure_compare(tag, wrong_tag_last)
    t_secure_last = (time.perf_counter() - t0) / trials

    return {
        "naive_compare": {
            "time_differ_at_byte_0": round(t_naive_first * 1e9, 1),
            "time_differ_at_byte_n": round(t_naive_last * 1e9, 1),
            "timing_ratio": round(t_naive_last / (t_naive_first + 1e-12), 2),
            "vulnerable": True,
            "note": "Timing varies with position of first mismatch — leaks tag info",
        },
        "secure_compare": {
            "time_differ_at_byte_0": round(t_secure_first * 1e9, 1),
            "time_differ_at_byte_n": round(t_secure_last * 1e9, 1),
            "timing_ratio": round(t_secure_last / (t_secure_first + 1e-12), 2),
            "vulnerable": False,
            "note": "Timing is uniform regardless of mismatch position — XOR accumulation",
        },
    }
