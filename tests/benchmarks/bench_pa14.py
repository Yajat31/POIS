"""
PA#14 Benchmark — Standard vs CRT RSA Decryption

For 1024-bit and 2048-bit keys:
  - Run 1000 decryptions using standard m = c^d mod n
  - Run 1000 decryptions using CRT (dp, dq, q_inv)
  - Report time per decryption and speedup ratio (expect ≈ 3-4x)
  - Verify results match across all 1000 messages
  - Save to docs/results/pa14_crt_bench.json
"""

import os, sys, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "../../docs/results")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def run_pa14_benchmark(bit_sizes=None, n_dec=1000) -> dict:
    from src.pa12_rsa.rsa import rsa_keygen, rsa_enc, rsa_dec
    from src.pa14_crt_attack.crt_attack import rsa_dec_crt

    if bit_sizes is None:
        bit_sizes = [1024, 2048]

    print(f"\n{'='*70}")
    print(f"PA#14 RSA Decryption Benchmark — {n_dec} decryptions per key size")
    print(f"{'='*70}")
    print(f"{'bits':>6}  {'std_ms':>10}  {'crt_ms':>10}  {'speedup':>10}  {'match':>8}")
    print(f"{'-'*60}")

    all_results = {}
    for bits in bit_sizes:
        print(f"  Generating {bits}-bit RSA key...", end=" ", flush=True)
        pk, sk = rsa_keygen(bits=bits)
        print("done")

        messages = [(i * 7 + 13) % (pk.n - 2) + 1 for i in range(n_dec)]
        ciphertexts = [rsa_enc(pk, m) for m in messages]

        # Standard decryption
        t0 = time.perf_counter()
        std_results = [rsa_dec(sk, c) for c in ciphertexts]
        t_std = (time.perf_counter() - t0) * 1000  # ms

        # CRT decryption
        t0 = time.perf_counter()
        crt_results = [rsa_dec_crt(sk, c) for c in ciphertexts]
        t_crt = (time.perf_counter() - t0) * 1000  # ms

        match = std_results == crt_results
        speedup = t_std / t_crt if t_crt > 0 else float("inf")

        row = {
            "bits": bits,
            "n_decryptions": n_dec,
            "std_total_ms": round(t_std, 2),
            "crt_total_ms": round(t_crt, 2),
            "std_per_dec_ms": round(t_std / n_dec, 4),
            "crt_per_dec_ms": round(t_crt / n_dec, 4),
            "speedup": round(speedup, 2),
            "results_match": match,
        }
        all_results[str(bits)] = row
        print(f"{bits:>6}  {t_std/n_dec*1000:>10.3f}  {t_crt/n_dec*1000:>10.3f}  "
              f"{speedup:>10.2f}x  {'✅' if match else '❌':>8}")

    out = os.path.join(OUTPUT_DIR, "pa14_crt_bench.json")
    with open(out, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nSaved to {out}")
    return all_results


def run_hastad_demo():
    """Demonstrate Håstad's e=3 attack with a concrete recovery."""
    from src.pa14_crt_attack.crt_attack import demo_hastad_e3
    print(f"\n--- Håstad's e=3 Attack ---")
    result = demo_hastad_e3(bits=128)
    status = "✅ SUCCESS" if result["attack_succeeded"] else "❌ FAILED"
    print(f"  m={result['plaintext']}, recovered={result['recovered_plaintext']}  {status}")
    return result


if __name__ == "__main__":
    run_pa14_benchmark(bit_sizes=[1024], n_dec=100)   # 100 for speed; 1000 for full
    run_hastad_demo()
