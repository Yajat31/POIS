"""
PA#1 Empirical Demo — NIST SP 800-22 Statistical Tests

Runs three NIST-style tests on the PRG output:
  1. Frequency (monobit) test — p-value for proportion of 1s
  2. Runs test               — p-value for alternating run lengths
  3. Serial (2-gram) test    — p-value for bigram uniformity

Reports: PASS/FAIL per test with p-values (threshold 0.01).
Saves results to docs/results/pa01_nist_results.json
"""

import os, sys, json, math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from src.pa01_owf_prg.owf import PRG, OWF, run_statistical_tests
from src.foundations.dlp_group import DEMO_PARAMS

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "../../docs/results")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def run_pa01_nist_demo(n_bits: int = 10000, seed: int = 42) -> dict:
    """Run all three NIST-style tests on PRG output and print results."""
    owf = OWF(DEMO_PARAMS)
    prg = PRG(owf)
    prg.seed(seed)
    bits = prg.next_bits(n_bits)

    results = run_statistical_tests(bits)
    all_pass = all(r["pass"] for r in results)

    output = {
        "n_bits": n_bits,
        "seed": seed,
        "all_pass": all_pass,
        "tests": results,
    }

    print(f"\n{'='*60}")
    print(f"PA#1 NIST Statistical Tests — PRG output ({n_bits} bits, seed={seed})")
    print(f"{'='*60}")
    for r in results:
        status = "✅ PASS" if r["pass"] else "❌ FAIL"
        print(f"  {r.get('test', r.get('name', '?')):30s}  p-value: {r.get('p_value', 0):.4f}  {status}")
    print(f"{'='*60}")
    print(f"Overall: {'ALL PASS ✅' if all_pass else 'SOME FAILURES ❌'}")

    out_path = os.path.join(OUTPUT_DIR, "pa01_nist_results.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Saved to {out_path}")
    return output


def owf_hardness_demo(n_trials: int = 200) -> dict:
    """Verify OWF inversion fails on random x values."""
    from src.pa01_owf_prg.owf import OWF
    owf = OWF(DEMO_PARAMS)
    result = owf.verify_hardness(n_trials)
    print(f"\nOWF Hardness: {result}")
    return result


def owp_demo():
    """Demonstrate OWP is a permutation on the DLP subgroup."""
    from src.pa01_owf_prg.owp import OWP_DLP, owf_to_owp_demo, owp_to_prg_demo
    print("\n--- OWP Demo ---")
    r1 = owf_to_owp_demo(DEMO_PARAMS)
    print(f"OWF→OWP: is_permutation={r1['is_permutation']}")
    r2 = owp_to_prg_demo(DEMO_PARAMS)
    print(f"OWP→PRG: seed={r2['seed']} output={r2['prg_output_hex']}")
    return {"owf_to_owp": r1, "owp_to_prg": r2}


if __name__ == "__main__":
    run_pa01_nist_demo()
    owf_hardness_demo()
    owp_demo()
