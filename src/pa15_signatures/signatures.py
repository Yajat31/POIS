"""
PA#15 — Digital Signatures (Hash-then-Sign)

Construction: Sign(sk, m) = H(m)^d mod n
              Verify(vk, m, σ) = (σ^e mod n == H(m))

Uses PA#8 DLP hash for H, PA#12 RSA for (d, e, n).
Hash-then-sign prevents existential forgery via multiplicative structure.

Demos:
  - Multiplicative forgery on raw RSA signing (without hash)
  - EUF-CMA game: 50 queries, fresh-message forgery fails
  - Verification fails after message tampering

Depends on: PA#12 (RSA), PA#8 (DLPHash)
"""

from __future__ import annotations
from src.pa12_rsa.rsa import RSAPublicKey, RSAPrivateKey, rsa_keygen
from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params, DEMO_PARAMS
from src.common.math_utils import modexp
from src.common.bytes_utils import bytes_to_int, int_to_bytes
from src.common.randomness import random_bytes


def _hash_message(m: bytes, hash_fn: DLPHash) -> int:
    """Hash message m and return as integer for RSA signing."""
    digest = hash_fn.hash(m)
    h_int = bytes_to_int(digest) % hash_fn.params.p
    if h_int == 0:
        h_int = 1
    return h_int


def Sign(sk: RSAPrivateKey, m: bytes, hash_fn: DLPHash | None = None) -> bytes:
    """Sign message m: σ = H(m)^d mod n."""
    if hash_fn is None:
        params = gen_dlp_hash_params(DEMO_PARAMS)
        hash_fn = DLPHash(params, block_size=16)
    h = _hash_message(m, hash_fn)
    # Reduce h mod n for RSA domain
    h_mod_n = h % sk.n or 1
    sigma = modexp(h_mod_n, sk.d, sk.n)
    n_bytes = (sk.n.bit_length() + 7) // 8
    return int_to_bytes(sigma, n_bytes)


def Verify(vk: RSAPublicKey, m: bytes, sigma: bytes, hash_fn: DLPHash | None = None) -> bool:
    """Verify signature: check σ^e mod n == H(m) mod n."""
    if hash_fn is None:
        params = gen_dlp_hash_params(DEMO_PARAMS)
        hash_fn = DLPHash(params, block_size=16)
    h = _hash_message(m, hash_fn) % vk.n or 1
    sigma_int = bytes_to_int(sigma)
    recovered = modexp(sigma_int, vk.e, vk.n)
    return recovered == h


def demo_multiplicative_forgery(pk: RSAPublicKey, sk: RSAPrivateKey) -> dict:
    """Demonstrate forgery on raw RSA signing (without hashing).

    Raw RSA signing: σ = m^d mod n.
    Forgery: given σ1 = m1^d and σ2 = m2^d,
             σ1 * σ2 mod n is a valid signature for m1*m2 mod n.
    """
    m1, m2 = 3, 7
    sig1 = modexp(m1, sk.d, sk.n)
    sig2 = modexp(m2, sk.d, sk.n)
    forged_msg = (m1 * m2) % sk.n
    forged_sig = (sig1 * sig2) % sk.n
    # Verify forged signature against forged message
    recovered = modexp(forged_sig, pk.e, pk.n)
    forgery_valid = recovered == forged_msg
    return {
        "m1": m1, "m2": m2, "forged_message": forged_msg,
        "forgery_valid": forgery_valid,
        "conclusion": "Raw RSA signing is malleable. Hash-then-sign prevents this.",
    }


def euf_cma_game_signatures(
    pk: RSAPublicKey, sk: RSAPrivateKey,
    hash_fn: DLPHash | None = None,
    num_queries: int = 50,
) -> dict:
    """EUF-CMA game for hash-then-sign RSA signatures."""
    if hash_fn is None:
        params = gen_dlp_hash_params(DEMO_PARAMS)
        hash_fn = DLPHash(params, block_size=16)

    queried = {}
    for _ in range(num_queries):
        m = random_bytes(16)
        sig = Sign(sk, m, hash_fn)
        queried[m] = sig

    fresh = random_bytes(16)
    while fresh in queried:
        fresh = random_bytes(16)

    forged_sig_bytes = next(iter(queried.values())) if queried else random_bytes(len(next(iter(queried.values()))) if queried else 64)
    forgery_valid = Verify(pk, fresh, forged_sig_bytes, hash_fn)
    return {
        "queries": num_queries, "forgery_accepted": forgery_valid,
        "security_holds": not forgery_valid,
    }
