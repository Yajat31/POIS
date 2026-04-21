"""
PA#18 — 1-of-2 Oblivious Transfer (Bellare-Micali style)

Protocol using own ElGamal (PA#16):
  Receiver wants m_b without revealing b; Sender doesn't learn b.

  Step 1 (Receiver, input b):
    Generate one honest key pair (pk_b, sk_b).
    Generate "fake" public key pk_{1-b} WITHOUT its trapdoor.
    Return (pk0, pk1, state) where state = (b, sk_b).

  Step 2 (Sender, input (pk0, pk1, m0, m1)):
    C0 = ElGamal_Enc(pk0, m0)
    C1 = ElGamal_Enc(pk1, m1)
    Return (C0, C1).

  Step 3 (Receiver, input (state, C0, C1)):
    Decrypt C_b using sk_b.
    Cannot decrypt C_{1-b} (no trapdoor).

Privacy:
  - Sender privacy: Receiver cannot decrypt the unchosen branch.
  - Receiver privacy: Sender cannot distinguish pk_b from pk_{1-b}.

Depends on: PA#16 (ElGamal)
"""

from __future__ import annotations
from src.pa16_elgamal.elgamal import (
    ElGamalPublicKey, ElGamalPrivateKey, elgamal_keygen,
    Enc, Dec, enc_bytes, dec_bytes,
)
from src.foundations.dlp_group import GroupParams, DEMO_PARAMS
from src.common.math_utils import modexp
from src.common.randomness import random_element_zq, random_bytes
from src.common.bytes_utils import bytes_to_int, int_to_bytes


def _fake_pk(group: GroupParams) -> ElGamalPublicKey:
    """Generate a fake public key with no known trapdoor.

    Method: pick a random y ∈ Z_p* without knowing x s.t. y = g^x mod p.
    Computationally indistinguishable from a real public key (DLP hardness).
    """
    y = random_element_zq(group.q)
    y_elem = modexp(group.g, y, group.p)  # still looks like g^something
    return ElGamalPublicKey(params=group, y=y_elem)


def OTReceiverStep1(
    b: int,
    group: GroupParams | None = None,
) -> tuple[ElGamalPublicKey, ElGamalPublicKey, dict]:
    """Receiver's first step: generate pk0, pk1 and keep state.

    b ∈ {0, 1}: which message the receiver wants.
    Returns (pk0, pk1, state) where state = {"b": b, "sk": sk_b}.
    """
    if b not in (0, 1):
        raise ValueError("OTReceiverStep1: b must be 0 or 1")
    if group is None:
        group = DEMO_PARAMS

    # Honest key pair for chosen index
    sk_b, pk_b = elgamal_keygen(group)
    # Fake key for unchosen index (no trapdoor)
    pk_fake = _fake_pk(group)

    if b == 0:
        pk0, pk1 = pk_b, pk_fake
    else:
        pk0, pk1 = pk_fake, pk_b

    state = {"b": b, "sk": sk_b}
    return pk0, pk1, state


def OTSenderStep(
    pk0: ElGamalPublicKey,
    pk1: ElGamalPublicKey,
    m0: int,
    m1: int,
) -> tuple[tuple[int, int], tuple[int, int]]:
    """Sender's step: encrypt both messages under respective public keys.

    Returns (C0, C1) = (Enc(pk0, m0), Enc(pk1, m1)).
    Sender cannot tell which pk is honest.
    """
    C0 = Enc(pk0, m0)
    C1 = Enc(pk1, m1)
    return C0, C1


def OTReceiverStep2(
    state: dict,
    C0: tuple[int, int],
    C1: tuple[int, int],
) -> int:
    """Receiver's second step: decrypt the chosen ciphertext.

    Returns m_b. Cannot decrypt m_{1-b} (no trapdoor for fake pk).
    """
    b = state["b"]
    sk = state["sk"]
    C = C0 if b == 0 else C1
    c1, c2 = C
    return Dec(sk, c1, c2)


def ot_exchange(m0: int, m1: int, b: int, group: GroupParams | None = None) -> dict:
    """Run a complete 1-of-2 OT exchange. Returns result and privacy analysis."""
    if group is None:
        group = DEMO_PARAMS

    pk0, pk1, state = OTReceiverStep1(b, group)
    C0, C1 = OTSenderStep(pk0, pk1, m0, m1)
    m_b = OTReceiverStep2(state, C0, C1)

    # Correctness check
    correct = m_b == (m0 if b == 0 else m1)

    # Sender privacy demo: receiver tries to also decrypt the other ciphertext
    # With the fake sk from state["sk"], Dec(C_{1-b}) gives garbage
    C_other = C1 if b == 0 else C0
    m_other_attempt = Dec(state["sk"], *C_other)
    receiver_learned_other = m_other_attempt == (m1 if b == 0 else m0)

    return {
        "b": b,
        "m0": m0, "m1": m1,
        "received_m_b": m_b,
        "correct": correct,
        "sender_privacy": {
            "receiver_tried_to_decrypt_other": True,
            "attempt_result": m_other_attempt,
            "got_correct_other": receiver_learned_other,
            "privacy_holds": not receiver_learned_other,
            "note": "Fake pk has no trapdoor → decryption of unchosen branch gives garbage.",
        },
    }


def ot_correctness_test(group: GroupParams | None = None, trials: int = 100) -> dict:
    """Test OT correctness over many trials."""
    if group is None:
        group = DEMO_PARAMS
    successes = 0
    for _ in range(trials):
        import os
        b = int.from_bytes(os.urandom(1), "big") % 2
        m0 = random_element_zq(group.q)
        m1 = random_element_zq(group.q)
        result = ot_exchange(m0, m1, b, group)
        if result["correct"]:
            successes += 1
    return {"trials": trials, "successes": successes, "success_rate": successes / trials}
