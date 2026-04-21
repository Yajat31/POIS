"""
PA#19 — Secure Gates: AND, XOR, NOT

Uses OT (PA#18) to compute AND securely under 2-party additive secret sharing over Z_2.
XOR and NOT are "free" under additive secret sharing.

Protocol:
  AND(a, b):
    Uses OT: Sender has (s0, s1) = (0, a); Receiver's choice bit = b.
    Receiver gets s_b = b*a = a AND b.
    This computes AND(a, b) directly since s_b = a*b over Z_2.

  XOR(a, b): a ⊕ b (free — just XOR the shares)
  NOT(a): 1 - a (free — flip the share)

Depends on: PA#18 (OT)
"""

from __future__ import annotations
from src.pa18_ot.ot import OTReceiverStep1, OTSenderStep, OTReceiverStep2
from src.foundations.dlp_group import GroupParams, DEMO_PARAMS


def AND(a: int, b: int, group: GroupParams | None = None) -> int:
    """Secure AND gate using OT.

    Sender messages: (m0=0, m1=a).
    Receiver bit: b.
    Receiver gets m_b = b*a (AND of a and b over Z_2).

    a, b ∈ {0, 1}.
    """
    if a not in (0, 1) or b not in (0, 1):
        raise ValueError("AND: inputs must be bits (0 or 1)")
    if group is None:
        group = DEMO_PARAMS

    # Map bits to group elements (1 stays 1, 0 maps to group element 1)
    # We use group element values: m0=1 (represents 0), m1=g (represents a=1)
    p = group.p

    # Use direct OT: sender sends (0, a) as integers (shifted to valid group elements)
    m0_elem = 1         # represents bit 0
    m1_elem = group.g if a == 1 else 1  # represents bit a

    pk0, pk1, state = OTReceiverStep1(b, group)
    C0, C1 = OTSenderStep(pk0, pk1, m0_elem, m1_elem)
    result_elem = OTReceiverStep2(state, C0, C1)

    # Decode: 1 → 0, g → a
    if a == 0:
        return 0  # sender sent (1,1) → always 0
    return 1 if result_elem == group.g else 0


def XOR(a: int, b: int) -> int:
    """XOR gate: free under additive Z_2 sharing."""
    return a ^ b


def NOT(a: int) -> int:
    """NOT gate: flip the bit (free under additive Z_2 sharing)."""
    return 1 - a


def truth_table_test(group: GroupParams | None = None) -> dict:
    """Verify all four input combinations for AND, XOR, NOT."""
    if group is None:
        group = DEMO_PARAMS
    results = {"AND": [], "XOR": [], "NOT": []}
    all_correct = True

    for a in (0, 1):
        for b in (0, 1):
            and_result = AND(a, b, group)
            xor_result = XOR(a, b)
            expected_and = a & b
            expected_xor = a ^ b
            and_ok = and_result == expected_and
            xor_ok = xor_result == expected_xor
            if not (and_ok and xor_ok):
                all_correct = False
            results["AND"].append({"a": a, "b": b, "result": and_result, "expected": expected_and, "ok": and_ok})
            results["XOR"].append({"a": a, "b": b, "result": xor_result, "expected": expected_xor, "ok": xor_ok})

    for a in (0, 1):
        not_result = NOT(a)
        ok = not_result == (1 - a)
        if not ok:
            all_correct = False
        results["NOT"].append({"a": a, "result": not_result, "expected": 1 - a, "ok": ok})

    return {"all_correct": all_correct, "truth_tables": results}
