"""
PA#9 — Birthday Attack on Hash Functions

Implements:
  - birthday_attack(hash_fn, n, num_trials): naive dict-based collision finder
  - floyd_collision_attack(hash_fn, n): Floyd's cycle-finding (tortoise-and-hare)

Experiments:
  - For n ∈ {8, 10, 12, 14, 16}: 100 trials, compare to theoretical 2^(n/2) bound
  - On truncated PA#8 DLP hash at n=16
  - Contextualized cost for MD5 and SHA-1

Depends on: PA#8 (DLPHash)
No external crypto libraries.
"""

from __future__ import annotations
import os
import math
from typing import Callable
from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params, DEMO_PARAMS


# ─────────────────────────────────────────────────────────────
#  Birthday Attack (naive dictionary approach)
# ─────────────────────────────────────────────────────────────

def birthday_attack(
    hash_fn: Callable[[bytes], int],
    n: int,
    max_evaluations: int = 1_000_000,
) -> dict:
    """Find a collision in hash_fn with n-bit output using a dictionary.

    hash_fn should map bytes → int (n-bit output).
    Expected evaluations ≈ 2^(n/2) (birthday bound).

    Returns:
        dict with collision pair, evaluation count, and analysis.
    """
    seen = {}  # hash_value → input bytes
    evaluations = 0

    while evaluations < max_evaluations:
        x = os.urandom(8)
        h = hash_fn(x) & ((1 << n) - 1)  # truncate to n bits
        evaluations += 1

        if h in seen and seen[h] != x:
            return {
                "collision_found": True,
                "evaluations": evaluations,
                "birthday_bound": int(2 ** (n / 2)),
                "ratio": round(evaluations / (2 ** (n / 2)), 3),
                "x1": seen[h].hex(),
                "x2": x.hex(),
                "hash_value": h,
                "n_bits": n,
            }
        seen[h] = x

    return {
        "collision_found": False,
        "evaluations": evaluations,
        "n_bits": n,
        "note": f"No collision found in {max_evaluations} evaluations (n={n}).",
    }


def birthday_attack_trials(
    hash_fn: Callable[[bytes], int],
    n: int,
    num_trials: int = 100,
) -> dict:
    """Run birthday_attack num_trials times and collect statistics.

    Returns distribution of evaluations until first collision,
    compared to theoretical birthday bound 2^(n/2).
    """
    evals_list = []
    collisions_found = 0
    max_per_trial = max(10 * int(2 ** (n / 2)), 1000)

    for _ in range(num_trials):
        result = birthday_attack(hash_fn, n, max_evaluations=max_per_trial)
        if result["collision_found"]:
            evals_list.append(result["evaluations"])
            collisions_found += 1

    if not evals_list:
        return {
            "n_bits": n,
            "num_trials": num_trials,
            "collisions_found": 0,
            "note": "No collisions found in any trial",
        }

    mean_evals = sum(evals_list) / len(evals_list)
    birthday_bound = 2 ** (n / 2)

    return {
        "n_bits": n,
        "num_trials": num_trials,
        "collisions_found": collisions_found,
        "mean_evaluations": round(mean_evals, 1),
        "birthday_bound": round(birthday_bound, 1),
        "mean_over_bound": round(mean_evals / birthday_bound, 3),
        "min_evals": min(evals_list),
        "max_evals": max(evals_list),
        "evals_distribution": evals_list[:10],  # first 10 for inspection
    }


# ─────────────────────────────────────────────────────────────
#  Floyd's Cycle-Finding (Tortoise-and-Hare)
# ─────────────────────────────────────────────────────────────

def floyd_collision_attack(
    hash_fn: Callable[[bytes], int],
    n: int,
    max_steps: int = 1_000_000,
) -> dict:
    """Floyd's cycle-finding applied to hash collision search.

    Maps the n-bit hash output space to itself via f(x) = hash(x).
    Uses tortoise-and-hare to find a cycle, then recovers a collision pair.

    Note: Floyd's algorithm finds a cycle in a function iteration sequence,
    which gives a second pre-image relative to the starting point.

    Returns:
        dict with collision pair and evaluation count.
    """
    mask = (1 << n) - 1

    def f(x: int) -> int:
        """Iterate hash: f(x) = H(x) truncated to n bits."""
        return hash_fn(x.to_bytes(8, "big")) & mask

    # Phase 1: Find meeting point
    tortoise = f(0)
    hare = f(f(0))
    steps = 2

    while tortoise != hare and steps < max_steps:
        tortoise = f(tortoise)
        hare = f(f(hare))
        steps += 2

    if tortoise != hare:
        return {
            "collision_found": False,
            "steps": steps,
            "n_bits": n,
            "note": "Cycle not found within max_steps",
        }

    # Phase 2: Find cycle start (the collision point)
    tortoise = 0
    collision_steps = steps
    while tortoise != hare:
        tortoise = f(tortoise)
        hare = f(hare)
        collision_steps += 1

    # tortoise = hare = cycle start point μ
    # The collision: f(x) = f(y) where x and y are different pre-images
    x_val = tortoise  # cycle start
    y_val = f(tortoise)  # one step further

    # Find actual collision: two distinct inputs with same hash
    # Walk sequence to find predecessor
    collision_input_1 = x_val.to_bytes(8, "big")
    collision_input_2 = y_val.to_bytes(8, "big")
    h1 = hash_fn(collision_input_1) & mask
    h2 = hash_fn(collision_input_2) & mask

    # These may not form a direct collision — we need cycle length λ
    # Find λ: length of cycle
    lambda_len = 1
    runner = f(x_val)
    while runner != x_val and lambda_len < max_steps:
        runner = f(runner)
        lambda_len += 1

    return {
        "collision_found": h1 == h2 and collision_input_1 != collision_input_2,
        "steps": collision_steps + lambda_len,
        "n_bits": n,
        "cycle_start": x_val,
        "cycle_length": lambda_len,
        "input1": collision_input_1.hex(),
        "input2": collision_input_2.hex(),
        "hash1": h1,
        "hash2": h2,
        "birthday_bound": int(2 ** (n / 2)),
        "method": "Floyd's cycle-finding (tortoise-and-hare)",
    }


# ─────────────────────────────────────────────────────────────
#  Experiment: Run across n values and plot
# ─────────────────────────────────────────────────────────────

def run_birthday_experiments(
    n_values: list[int] = None,
    num_trials: int = 100,
    use_dlp_hash: bool = True,
) -> list[dict]:
    """Run birthday attack experiments for n ∈ n_values.

    Compares empirical mean evaluations to theoretical 2^(n/2).
    """
    if n_values is None:
        n_values = [8, 10, 12, 14, 16]

    if use_dlp_hash:
        params = gen_dlp_hash_params(DEMO_PARAMS)
        dlp = DLPHash(params, block_size=16)

        def hash_fn(x: bytes) -> int:
            return int.from_bytes(dlp.hash(x), "big")
    else:
        # Simple toy hash: XOR-fold
        def hash_fn(x: bytes) -> int:
            acc = 0
            for b in x:
                acc = (acc * 31 + b) & 0xFFFFFFFF
            return acc

    results = []
    for n in n_values:
        stats = birthday_attack_trials(hash_fn, n, num_trials)
        results.append(stats)
        print(
            f"n={n:2d}: mean={stats.get('mean_evaluations','N/A'):8.1f}  "
            f"bound={stats.get('birthday_bound','N/A'):8.1f}  "
            f"ratio={stats.get('mean_over_bound','N/A'):.3f}"
        )

    return results


def compute_md5_sha1_cost() -> dict:
    """Estimate birthday attack cost for MD5 (128-bit) and SHA-1 (160-bit)."""
    md5_bits = 128
    sha1_bits = 160
    md5_ops = 2 ** (md5_bits / 2)  # ≈ 2^64
    sha1_ops = 2 ** (sha1_bits / 2)  # ≈ 2^80
    return {
        "MD5": {
            "output_bits": md5_bits,
            "birthday_bound": f"2^{md5_bits//2} ≈ {md5_ops:.2e}",
            "practical_attack": "MD5 collisions found by Wang et al. 2004 (chosen-prefix, ≈2^39)",
        },
        "SHA-1": {
            "output_bits": sha1_bits,
            "birthday_bound": f"2^{sha1_bits//2} ≈ {sha1_ops:.2e}",
            "practical_attack": "SHAttered (2017): ≈2^63 SHA-1 compressions",
        },
        "rule": "Birthday bound: 2^(n/2) evaluations for n-bit hash → collision with prob ≈ 1/2",
    }
