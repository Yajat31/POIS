"""
PA#20 Benchmark — OT Call Counts + Wall-Clock for 8-bit Circuits

For each of the three mandatory circuits (equality, comparison, addition) at n=8:
  - Count AND gate calls (= OT calls)
  - Measure wall-clock time
  - Log transcript summary
  - Confirm output correctness vs plain Boolean evaluation

Also documents the full call-stack lineage:
  SecureEval → AND (PA#19) → OTSenderStep/OTReceiverStep (PA#18) → ElGamal (PA#16) → DLP group (PA#13)
"""

import os, sys, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from src.pa20_mpc.mpc import (
    build_equality_circuit, build_comparison_circuit, build_addition_circuit, SecureEval,
)
from src.foundations.dlp_group import DEMO_PARAMS

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "../../docs/results")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def run_pa20_benchmark(n_bits: int = 8) -> dict:
    group = DEMO_PARAMS

    test_cases = [
        ([1, 0, 1, 1, 0, 1, 1, 0], [1, 0, 1, 1, 0, 1, 1, 0]),   # equal
        ([1, 1, 0, 0, 1, 0, 1, 1], [0, 1, 1, 0, 0, 1, 0, 0]),   # x > y
        ([0, 0, 1, 1, 0, 1, 0, 1], [1, 1, 0, 0, 1, 0, 1, 0]),   # x < y
    ]

    circuits = {
        "equality":   (build_equality_circuit(n_bits),   lambda x, y: int(x == y)),
        "comparison": (build_comparison_circuit(n_bits), lambda x, y: int(x > y)),
        "addition":   (build_addition_circuit(n_bits),   lambda x, y: (x + y) % (2 ** n_bits)),
    }

    results = {}

    print(f"\n{'='*75}")
    print(f"PA#20 Secure MPC Benchmark — n={n_bits} bits, {len(test_cases)} test inputs")
    print(f"{'='*75}")
    print(f"{'Circuit':12}  {'AND/OT calls':14}  {'time_s':8}  {'correct':9}")
    print(f"{'-'*60}")

    for cname, (circuit, ref_fn) in circuits.items():
        x_bits, y_bits = test_cases[0]
        x_int = int("".join(str(b) for b in x_bits), 2)
        y_int = int("".join(str(b) for b in y_bits), 2)

        t0 = time.perf_counter()
        out_bits, meta = SecureEval(circuit, x_bits, y_bits, group)
        elapsed = time.perf_counter() - t0

        and_calls = meta["and_calls"]

        if cname == "addition":
            out_val = int("".join(str(b) for b in out_bits), 2)
            expected = ref_fn(x_int, y_int)
            correct = out_val == expected
        else:
            out_val = out_bits[0]
            expected = ref_fn(x_int, y_int)
            correct = out_val == expected

        results[cname] = {
            "n_bits": n_bits,
            "x_int": x_int, "y_int": y_int,
            "output": out_val, "expected": expected,
            "correct": correct,
            "and_ot_calls": and_calls,
            "wall_clock_s": round(elapsed, 4),
            "transcript_gates": meta["total_gates"],
        }
        status = "✅" if correct else "❌"
        print(f"{cname:12}  {and_calls:>14}  {elapsed:>8.4f}  {status}")

    results["lineage"] = (
        "SecureEval (PA#20) → AND (PA#19) → OTReceiverStep1/OTSenderStep/OTReceiverStep2 (PA#18) "
        "→ ElGamal Enc/Dec (PA#16) → safe-prime DLP group (gen_group via PA#13 Miller-Rabin)"
    )

    # Also run all 3 test cases for equality to validate correctness
    eq_circuit = build_equality_circuit(n_bits)
    eq_results = []
    for x_bits, y_bits in test_cases:
        x_int = int("".join(str(b) for b in x_bits), 2)
        y_int = int("".join(str(b) for b in y_bits), 2)
        out, _ = SecureEval(eq_circuit, x_bits, y_bits, group)
        eq_results.append({"x": x_int, "y": y_int, "eq_output": out[0], "expected": int(x_int == y_int)})
    results["equality_all_cases"] = eq_results

    out_path = os.path.join(OUTPUT_DIR, "pa20_mpc_bench.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out_path}")
    return results


if __name__ == "__main__":
    run_pa20_benchmark(n_bits=8)
