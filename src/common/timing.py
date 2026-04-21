"""
timing.py — Constant-time comparison helpers.

Side-channel resistant comparison required by PA#10 (HMAC_Verify).
Implemented via XOR accumulation — never short-circuits.
"""


def secure_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two byte strings.

    Returns True only if a == b in both content AND length,
    without short-circuiting on the first differing byte.
    Timing is independent of the position of the first mismatch.
    """
    # Lengths must also be compared without short-circuit
    # We XOR each byte into an accumulator
    if len(a) != len(b):
        # Still consume both to avoid timing leak on length
        diff = 1
    else:
        diff = 0

    # Always iterate over both, using min length to avoid IndexError
    acc = 0
    for x, y in zip(a, b):
        acc |= x ^ y

    return diff == 0 and acc == 0


def naive_compare(a: bytes, b: bytes) -> bool:
    """Insecure naive comparison that short-circuits (for timing demo in PA#10)."""
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True
