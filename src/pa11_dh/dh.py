"""
PA#11 — Diffie-Hellman Key Exchange

Implements:
  - Alice and Bob step APIs for authenticated DH
  - Group setup using safe prime from PA#13
  - MITM (Man-in-the-Middle) attack demonstration
  - CDH hardness brute-force demo for small parameters

Interface:
  dh_alice_step1() -> (a, A)          Alice's private/public key
  dh_bob_step1()   -> (b, B)          Bob's private/public key
  dh_alice_step2(a, B) -> K           Alice computes shared secret
  dh_bob_step2(b, A) -> K             Bob computes shared secret

Depends on: PA#13 (gen_safe_prime via dlp_group), src/foundations/dlp_group.py
No external crypto libraries.
"""

from __future__ import annotations
from src.foundations.dlp_group import GroupParams, DEMO_PARAMS, gen_group
from src.common.math_utils import modexp
from src.common.randomness import random_element_zq
from src.common.bytes_utils import int_to_bytes

# Default group: use DEMO_PARAMS for fast demos; use gen_group(bits=512) for security
_DEFAULT_GROUP = DEMO_PARAMS


# ─────────────────────────────────────────────────────────────
#  DH Key Exchange
# ─────────────────────────────────────────────────────────────

def dh_alice_step1(group: GroupParams | None = None) -> tuple[int, int]:
    """Alice generates her private key a and public key A = g^a mod p.

    Returns (a, A).
    """
    if group is None:
        group = _DEFAULT_GROUP
    a = random_element_zq(group.q)
    A = modexp(group.g, a, group.p)
    return a, A


def dh_bob_step1(group: GroupParams | None = None) -> tuple[int, int]:
    """Bob generates his private key b and public key B = g^b mod p.

    Returns (b, B).
    """
    if group is None:
        group = _DEFAULT_GROUP
    b = random_element_zq(group.q)
    B = modexp(group.g, b, group.p)
    return b, B


def dh_alice_step2(a: int, B: int, group: GroupParams | None = None) -> int:
    """Alice computes the shared secret K = B^a mod p = g^(ab) mod p."""
    if group is None:
        group = _DEFAULT_GROUP
    return modexp(B, a, group.p)


def dh_bob_step2(b: int, A: int, group: GroupParams | None = None) -> int:
    """Bob computes the shared secret K = A^b mod p = g^(ab) mod p."""
    if group is None:
        group = _DEFAULT_GROUP
    return modexp(A, b, group.p)


def dh_exchange(group: GroupParams | None = None) -> dict:
    """Complete honest DH exchange. Returns both parties' shared secrets."""
    if group is None:
        group = _DEFAULT_GROUP
    a, A = dh_alice_step1(group)
    b, B = dh_bob_step1(group)
    K_alice = dh_alice_step2(a, B, group)
    K_bob = dh_bob_step2(b, A, group)
    return {
        "A": A,
        "B": B,
        "K_alice": K_alice,
        "K_bob": K_bob,
        "match": K_alice == K_bob,
        "group_p": group.p,
        "group_q": group.q,
    }


# ─────────────────────────────────────────────────────────────
#  MITM (Man-in-the-Middle) Attack Demo
# ─────────────────────────────────────────────────────────────

def dh_mitm_attack(group: GroupParams | None = None) -> dict:
    """Demonstrate MITM attack on unauthenticated DH.

    Eve intercepts Alice's A and Bob's B, substitutes her own values.
    Result: Alice and Bob each share a key with Eve, not with each other.
    """
    if group is None:
        group = _DEFAULT_GROUP

    # Honest key generation
    a, A = dh_alice_step1(group)
    b, B = dh_bob_step1(group)

    # Eve generates her own key pair
    e, E = dh_alice_step1(group)  # Eve's ephemeral key

    # Eve intercepts: substitutes E for both A and B
    # Alice sees E (thinking it's from Bob), Bob sees E (thinking it's from Alice)
    K_alice_with_eve = dh_alice_step2(a, E, group)  # Alice computes "K" = E^a
    K_bob_with_eve = dh_bob_step2(b, E, group)      # Bob computes "K" = E^b
    K_eve_alice = dh_alice_step2(e, A, group)        # Eve ↔ Alice: A^e
    K_eve_bob = dh_bob_step2(e, B, group)            # Eve ↔ Bob: B^e

    return {
        "honest_public_keys": {"A": A, "B": B},
        "eve_public_key": E,
        "alice_thinks_shared_with_bob": K_alice_with_eve,
        "eve_key_to_alice": K_eve_alice,
        "alice_eve_keys_match": K_alice_with_eve == K_eve_alice,
        "bob_thinks_shared_with_alice": K_bob_with_eve,
        "eve_key_to_bob": K_eve_bob,
        "bob_eve_keys_match": K_bob_with_eve == K_eve_bob,
        "mitm_success": K_alice_with_eve == K_eve_alice and K_bob_with_eve == K_eve_bob,
        "alice_bob_actually_share": False,
        "explanation": (
            "Without authentication, Eve can substitute her own public key. "
            "Alice and Bob each believe they share a key with each other, "
            "but actually each shares a separate key with Eve."
        ),
    }


# ─────────────────────────────────────────────────────────────
#  CDH Hardness Demo (Brute Force for Small Parameters)
# ─────────────────────────────────────────────────────────────

def cdh_hardness_demo(group: GroupParams | None = None) -> dict:
    """Demonstrate CDH hardness by attempting brute-force DLP.

    For small group parameters (tiny q), brute-force DLP is feasible.
    Shows that recovering the shared secret from (g, g^a, g^b) requires
    solving DLP (or CDH directly).
    """
    if group is None:
        group = _DEFAULT_GROUP

    a, A = dh_alice_step1(group)
    b, B = dh_bob_step1(group)
    K_real = dh_alice_step2(a, B, group)

    # Attempt brute-force DLP to recover a from A = g^a mod p
    recovered_a = None
    evaluations = 0
    if group.q <= 100000:
        for candidate in range(group.q):
            evaluations += 1
            if modexp(group.g, candidate, group.p) == A:
                recovered_a = candidate
                break

    if recovered_a is not None:
        K_recovered = dh_alice_step2(recovered_a, B, group)
        attack_succeeded = K_recovered == K_real
    else:
        K_recovered = None
        attack_succeeded = False

    return {
        "group_order_q": group.q,
        "A": A,
        "B": B,
        "K_real": K_real,
        "brute_force_feasible": group.q <= 100000,
        "dlp_evaluations": evaluations,
        "recovered_a": recovered_a,
        "K_recovered": K_recovered,
        "attack_succeeded": attack_succeeded,
        "note": "For cryptographic q (≥ 2^256), brute-force DLP takes 2^128+ steps.",
    }
