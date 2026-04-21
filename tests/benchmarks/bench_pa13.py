"""
PA#13 Benchmark — Prime Generation: Candidate Counts vs Prime Number Theorem

For bit-sizes 512, 1024, 2048:
  - Run 10 prime-generation trials
  - Record candidate count per trial (how many candidates tested before finding a prime)
  - Compare empirical mean to PNT heuristic: ln(2^n) ≈ n * ln(2)
  - Report table + save JSON

PNT heuristic: probability that a random n-bit integer is prime ≈ 1/(n*ln2)
Expected candidates per prime ≈ n * ln(2) ≈ 0.693 * n
"""

import os, sys, json, math, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "../../docs/results")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def gen_prime_count_candidates(bits: int):
    """Generate a prime of the given bit size and return the candidate count."""
    from src.common.randomness import random_bytes
    from src.pa13_miller_rabin.miller_rabin import miller_rabin
    count = 0
    while True:
        # Generate random n-bit integer (force MSB and LSB set for odd)
        raw = random_bytes(bits // 8)
        candidate = int.from_bytes(raw, "big")
        # Force n bits
        candidate |= (1 << (bits - 1))
        candidate |= 1  # odd
        count += 1
        if miller_rabin(candidate, k=20):
            return candidate, count


def run_pa13_benchmark(bit_sizes=None, trials=10) -> dict:
    if bit_sizes is None:
        bit_sizes = [512, 1024, 2048]

    print(f"\n{'='*70}")
    print(f"PA#13 Prime Generation Benchmark — {trials} trials per bit size")
    print(f"{'='*70}")
    print(f"{'bits':>6}  {'mean_cands':>12}  {'PNT_expect':>12}  {'min':>8}  {'max':>8}  {'time_s':>8}")
    print(f"{'-'*70}")

    all_results = {}
    for bits in bit_sizes:
        pnt_expected = bits * math.log(2)
        counts = []
        times = []
        for _ in range(trials):
            t0 = time.perf_counter()
            _, cnt = gen_prime_count_candidates(bits)
            times.append(time.perf_counter() - t0)
            counts.append(cnt)
        mean_cnt = sum(counts) / len(counts)
        mean_t = sum(times) / len(times)
        row = {
            "bits": bits,
            "trials": trials,
            "mean_candidates": round(mean_cnt, 2),
            "pnt_expected": round(pnt_expected, 2),
            "ratio_mean_over_pnt": round(mean_cnt / pnt_expected, 3),
            "min_candidates": min(counts),
            "max_candidates": max(counts),
            "mean_time_s": round(mean_t, 4),
        }
        all_results[str(bits)] = row
        print(f"{bits:>6}  {mean_cnt:>12.2f}  {pnt_expected:>12.2f}  "
              f"{min(counts):>8}  {max(counts):>8}  {mean_t:>8.4f}")

    out = os.path.join(OUTPUT_DIR, "pa13_primegen_bench.json")
    with open(out, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nSaved to {out}")
    return all_results


if __name__ == "__main__":
    run_pa13_benchmark(trials=10)
