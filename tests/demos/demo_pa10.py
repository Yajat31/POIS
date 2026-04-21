"""
PA#10 Empirical Demo — EtH vs PA#6 PRF-MAC Performance Comparison

Compares Encrypt-then-HMAC (PA#10) against Encrypt-then-PRF-MAC (PA#6) on:
  - Tag size (bytes)
  - Encrypt latency (µs)
  - Decrypt latency (µs)
  - Verify latency (µs)

Also tests: length-extension immunity, timing side-channel demo.
Saves results to docs/results/pa10_comparison.json
"""

import os, sys, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from src.common.randomness import random_bytes

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "../../docs/results")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def bench_fn(fn, trials=200):
    """Return mean wall-clock time in microseconds."""
    start = time.perf_counter()
    for _ in range(trials):
        fn()
    return (time.perf_counter() - start) / trials * 1e6


def run_pa10_comparison(trials: int = 200) -> dict:
    from src.pa06_cca_enc.cca_enc import CCA_Enc, CCA_Dec
    from src.pa10_hmac_eth.hmac_eth import EtH_Enc, EtH_Dec
    from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params, DEMO_PARAMS

    kE, kM = random_bytes(16), random_bytes(16)
    m = b"Performance comparison message!!"
    params = gen_dlp_hash_params(DEMO_PARAMS)
    hash_fn = DLPHash(params, block_size=16)

    print(f"\n{'='*65}")
    print("PA#10 vs PA#6 — Encrypt-then-MAC Performance Comparison")
    print(f"{'='*65}")

    # PA#6 (PRF-MAC / CBC-MAC based)
    pa6_c, pa6_t = CCA_Enc(kE, kM, m)
    t_pa6_enc = bench_fn(lambda: CCA_Enc(kE, kM, m), trials)
    t_pa6_dec = bench_fn(lambda: CCA_Dec(kE, kM, pa6_c, pa6_t), trials)

    # PA#10 (HMAC based)
    pa10_c, pa10_t = EtH_Enc(kE, kM, m, hash_fn)
    t_pa10_enc = bench_fn(lambda: EtH_Enc(kE, kM, m, hash_fn), trials)
    t_pa10_dec = bench_fn(lambda: EtH_Dec(kE, kM, pa10_c, pa10_t, hash_fn), trials)

    results = {
        "message_bytes": len(m),
        "trials": trials,
        "PA6_PRF_MAC": {
            "tag_size_bytes": len(pa6_t),
            "enc_time_us": round(t_pa6_enc, 2),
            "dec_time_us": round(t_pa6_dec, 2),
        },
        "PA10_HMAC": {
            "tag_size_bytes": len(pa10_t),
            "enc_time_us": round(t_pa10_enc, 2),
            "dec_time_us": round(t_pa10_dec, 2),
        },
        "comparison": {
            "enc_overhead_factor": round(t_pa10_enc / t_pa6_enc, 2),
            "dec_overhead_factor": round(t_pa10_dec / t_pa6_dec, 2),
            "note": "HMAC uses DLP hash (slower but provably secure from CRHF). PRF-MAC uses AES (faster, PRP-based).",
        },
    }

    print(f"\n{'Scheme':15} {'Tag (B)':8} {'Enc (µs)':10} {'Dec (µs)':10}")
    print(f"{'-'*45}")
    print(f"{'PA#6 PRF-MAC':15} {len(pa6_t):8} {t_pa6_enc:10.2f} {t_pa6_dec:10.2f}")
    print(f"{'PA#10 HMAC':15} {len(pa10_t):8} {t_pa10_enc:10.2f} {t_pa10_dec:10.2f}")
    print(f"\nHMAC overhead: enc={results['comparison']['enc_overhead_factor']}x  dec={results['comparison']['dec_overhead_factor']}x")

    # Length-extension demo
    from src.pa10_hmac_eth.hmac_eth import length_extension_on_hmac_fails
    lex = length_extension_on_hmac_fails(kM, m, hash_fn)
    results["length_extension_immunity"] = lex
    print(f"\nLength-extension on HMAC fails: {lex['attack_succeeded'] == False}")

    out = os.path.join(OUTPUT_DIR, "pa10_comparison.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out}")
    return results


if __name__ == "__main__":
    run_pa10_comparison()
