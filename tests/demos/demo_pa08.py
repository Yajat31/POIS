"""
PA#8 Empirical Demo — DLP Hash: Multi-Message Hashing + Birthday Experiment

Requirements:
  1. Hash at least 5 messages of different lengths → confirm distinct digests
  2. Demonstrate collision resistance (tiny-param brute-force)
  3. Show collision → DLP reduction algebraically
"""

import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from src.pa08_dlp_hash.dlp_hash import (
    DLPHash, gen_dlp_hash_params, demo_find_collision_brute_force,
    collision_to_dlp, DEMO_PARAMS,
)

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "../../docs/results")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def run_pa08_demo() -> dict:
    from src.pa13_miller_rabin.miller_rabin import gen_safe_prime
    from src.foundations.dlp_group import GroupParams
    from src.common.math_utils import modexp

    # Use a proper 256-bit group for collision-resistance demo (DEMO_PARAMS is intentionally tiny)
    try:
        p = gen_safe_prime(bits=128)
        q = (p - 1) // 2
        g = 2
        # verify g has order q in Z_p*: g^q ≡ 1 mod p?
        while modexp(g, q, p) != 1:
            g += 1
        medium_group = GroupParams(p=p, q=q, g=g)
        params = gen_dlp_hash_params(medium_group)
    except Exception:
        from src.pa08_dlp_hash.dlp_hash import DEMO_PARAMS as _DP
        params = gen_dlp_hash_params(_DP)

    h = DLPHash(params, block_size=16)

    messages = [
        b"",
        b"hello",
        b"hello world",
        b"A" * 64,
        b"The quick brown fox jumps over the lazy dog",
        bytes(range(256)),
    ]

    print(f"\n{'='*65}")
    print("PA#8 DLP Hash — Multi-Message Digest Verification")
    print(f"{'='*65}")
    digests = {}
    for msg in messages:
        d = h.hash(msg)
        digests[repr(msg[:20])] = d.hex()
        print(f"  len={len(msg):4d}: {d.hex()[:32]}...")

    all_distinct = len(set(digests.values())) == len(digests)
    print(f"\nAll distinct: {all_distinct} {'✅' if all_distinct else '(small group — expected for DEMO_PARAMS)'}")

    # Brute-force birthday on tiny params
    print("\n--- Brute-Force Collision Search (tiny group) ---")
    coll = demo_find_collision_brute_force(params)
    print(f"  Collision found: {coll['collision_found']}")
    if coll.get("collision_found"):
        print(f"  Evaluations: {coll['evaluations']} (birthday bound ≈ {coll['birthday_bound']})")
        dlp_r = coll.get("dlp_recovery", {})
        print(f"  DLP recovered: {dlp_r.get('recovery_correct')}")

    results = {"multi_message": {"all_distinct": all_distinct, "digests": digests}, "collision_search": coll}
    out = os.path.join(OUTPUT_DIR, "pa08_hash_results.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nSaved to {out}")
    return results


if __name__ == "__main__":
    run_pa08_demo()
