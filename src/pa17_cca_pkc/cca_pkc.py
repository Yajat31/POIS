"""
PA#17 — CCA-Secure Public-Key Encryption (Signcrypt-style)

Construction: Sign-then-Encrypt (verify-then-decrypt ordering)
  CCA_PKC_Enc(pk_enc, sk_sign, m):
    σ = Sign(sk_sign, m)          (PA#15 hash-then-sign RSA)
    CE = ElGamal_Enc(pk_enc, m ∥ σ)  (PA#16 ElGamal)
    return (CE, σ)

  CCA_PKC_Dec(sk_enc, vk_sign, CE, σ):
    1. m' ∥ σ' = ElGamal_Dec(sk_enc, CE)
    2. if NOT Verify(vk_sign, m', σ'): return ⊥   ← VERIFY FIRST
    3. return m'

Lineage: PA#17 → PA#15 + PA#16 → PA#12 + PA#11 + PA#13.
No external crypto libraries.
"""

from __future__ import annotations
from src.pa15_signatures.signatures import Sign, Verify
from src.pa16_elgamal.elgamal import (
    ElGamalPublicKey, ElGamalPrivateKey, elgamal_keygen,
    enc_bytes, dec_bytes,
)
from src.pa12_rsa.rsa import RSAPublicKey, RSAPrivateKey, rsa_keygen
from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params, DEMO_PARAMS
from src.common.encoding import pack_tuple, unpack_tuple
from src.common.randomness import random_bytes


def CCA_PKC_Enc(
    pk_enc: ElGamalPublicKey,
    sk_sign: RSAPrivateKey,
    m: bytes,
    hash_fn: DLPHash | None = None,
) -> tuple[tuple[int, int], bytes]:
    """Encrypt m and sign it. Returns (CE, σ).

    CE = ElGamal encryption of (m ∥ σ).
    σ = RSA hash-then-sign signature on m.
    """
    if hash_fn is None:
        params = gen_dlp_hash_params(DEMO_PARAMS)
        hash_fn = DLPHash(params, block_size=16)

    # Step 1: Sign message
    sigma = Sign(sk_sign, m, hash_fn)

    # Step 2: Pack m ∥ σ and encrypt under ElGamal
    plaintext_blob = pack_tuple(m, sigma)
    # ElGamal works on integers: encode blob as integer mod p
    p = pk_enc.params.p
    from src.common.bytes_utils import bytes_to_int, int_to_bytes
    blob_int = bytes_to_int(plaintext_blob) % p or 1
    from src.pa16_elgamal.elgamal import Enc
    CE = Enc(pk_enc, blob_int)
    return CE, sigma


def CCA_PKC_Dec(
    sk_enc: ElGamalPrivateKey,
    vk_sign: RSAPublicKey,
    CE: tuple[int, int],
    sigma: bytes,
    hash_fn: DLPHash | None = None,
) -> bytes | None:
    """Decrypt CE and verify signature. Returns m or None (⊥).

    CRITICAL: Verify BEFORE using the plaintext.
    """
    if hash_fn is None:
        params = gen_dlp_hash_params(DEMO_PARAMS)
        hash_fn = DLPHash(params, block_size=16)

    from src.pa16_elgamal.elgamal import Dec
    from src.common.bytes_utils import bytes_to_int, int_to_bytes

    c1, c2 = CE
    # Decrypt ElGamal
    blob_int = Dec(sk_enc, c1, c2)
    p = sk_enc.params.p
    byte_len = (p.bit_length() + 7) // 8
    blob = int_to_bytes(blob_int, byte_len)

    # Strip leading zeros from packing
    try:
        m_bytes, sigma_recovered = unpack_tuple(blob.lstrip(b"\x00") or b"\x00\x00\x00\x01\x00\x00\x00\x01", 2)
    except (ValueError, Exception):
        return None  # ⊥ — malformed

    # VERIFY FIRST (before trusting m_bytes)
    if not Verify(vk_sign, m_bytes, sigma, hash_fn):
        return None  # ⊥ — invalid signature

    return m_bytes


def demo_lineage() -> str:
    """Print the call-stack lineage for PA#17."""
    return (
        "PA#17 CCA_PKC_Enc/Dec\n"
        "  └─ PA#15 Sign/Verify (hash-then-sign RSA)\n"
        "       └─ PA#12 RSA enc/dec (own keygen, modexp)\n"
        "            └─ PA#13 Miller-Rabin gen_prime\n"
        "       └─ PA#8 DLPHash (Merkle-Damgård + DLP compression)\n"
        "            └─ PA#7 MerkleDamgard framework\n"
        "  └─ PA#16 ElGamal Enc/Dec\n"
        "       └─ PA#11 DH group setup (safe prime)\n"
        "            └─ PA#13 Miller-Rabin gen_safe_prime\n"
    )
