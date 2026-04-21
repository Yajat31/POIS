"""
PA#9 MD5/SHA-1 Context Calculation.

"Compute 2^(n/2) for n=128 (MD5) and n=160 (SHA-1). Express the result in terms
of modern CPU speed (e.g., if a CPU hashes 10^9 values/sec, how many seconds/years
does the attack take?). This contextualises why MD5 is broken and SHA-1 is deprecated."
"""

import os, json

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "../../docs/results")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def compute_hash_context(n: int, hash_name: str, hashes_per_sec: float) -> dict:
    bound = 2 ** (n / 2)
    seconds = bound / hashes_per_sec
    minutes = seconds / 60
    hours = minutes / 60
    days = hours / 24
    years = days / 365.25

    return {
        "hash_name": hash_name,
        "n_bits": n,
        "birthday_bound": f"2^{n//2} = {bound:.2e}",
        "hashes_per_sec": f"{hashes_per_sec:.0e}",
        "time_seconds": f"{seconds:.2e}",
        "time_years": f"{years:.2e}",
        "context": (
            f"At {hashes_per_sec:.0e} hashes/sec, a birthday attack on {hash_name} "
            f"(n={n}) requires 2^{n//2} evaluations, taking approx {years:.2e} years."
        )
    }

def run_pa09_context() -> dict:
    # Modern CPU/GPU speed assumption: 10 billion hashes per second (10^10)
    HASHES_PER_SEC = 10 ** 10

    print(f"\n{'='*70}")
    print(f"PA#9 Context Calculation — MD5 & SHA-1 Collision Resistance")
    print(f"Assumption: attacker can compute {HASHES_PER_SEC:.0e} hashes/sec")
    print(f"{'='*70}")

    md5_ctx = compute_hash_context(128, "MD5", HASHES_PER_SEC)
    sha1_ctx = compute_hash_context(160, "SHA-1", HASHES_PER_SEC)

    results = {
        "assumptions": {
            "hashes_per_sec": HASHES_PER_SEC,
            "description": "Modern high-end GPU cluster or custom ASIC speed estimate"
        },
        "MD5": md5_ctx,
        "SHA-1": sha1_ctx
    }

    for name, ctx in [("MD5", md5_ctx), ("SHA-1", sha1_ctx)]:
        print(f"\n{name} (n={ctx['n_bits']}):")
        print(f"  Birthday bound: {ctx['birthday_bound']} hashes")
        print(f"  Time required:  {ctx['time_years']} years")
        print(f"  Conclusion:     {ctx['context']}")
        
        if name == "MD5":
            print("  Note: Actual MD5 collisions are much faster due to cryptanalytic flaws (not just birthday bound).")

    out = os.path.join(OUTPUT_DIR, "pa09_context_calculation.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out}")
    return results

if __name__ == "__main__":
    run_pa09_context()
