"""
PA#9 Empirical Demo — Birthday Attack: 100-Trial Experiment with Plot

For n ∈ {8, 10, 12, 14, 16}:
  - Run 100 independent birthday attack trials
  - Record evaluations until first collision
  - Compare empirical mean to theoretical 2^(n/2)
  - Generate matplotlib plot with distribution and theory overlay
  - Save as docs/results/pa09_birthday_plot.png + pa09_birthday_data.json
"""

import os, sys, json, math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "../../docs/results")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_toy_hash(n: int):
    """Fast n-bit toy hash: polynomial rolling hash truncated to n bits."""
    mask = (1 << n) - 1
    def h(x: bytes) -> int:
        acc = 0x811C9DC5
        for byte in x:
            acc ^= byte
            acc = (acc * 0x01000193) & 0xFFFFFFFF
        return acc & mask
    return h


def run_pa09_experiment(n_values=None, num_trials=100) -> list[dict]:
    """Run birthday attack experiment for each n value."""
    from src.pa09_birthday.birthday import birthday_attack_trials
    if n_values is None:
        n_values = [8, 10, 12, 14, 16]

    all_results = []
    print(f"\n{'='*65}")
    print(f"PA#9 Birthday Attack — {num_trials} trials per n")
    print(f"{'='*65}")
    print(f"{'n':>4}  {'mean_evals':>12}  {'bound 2^(n/2)':>14}  {'ratio':>8}  {'min':>8}  {'max':>8}")
    print(f"{'-'*65}")

    for n in n_values:
        h = make_toy_hash(n)
        stats = birthday_attack_trials(h, n, num_trials=num_trials)
        all_results.append(stats)
        mean = stats.get("mean_evaluations", "N/A")
        bound = stats.get("birthday_bound", "N/A")
        ratio = stats.get("mean_over_bound", "N/A")
        mn = stats.get("min_evals", "N/A")
        mx = stats.get("max_evals", "N/A")
        print(f"{n:>4}  {str(mean):>12}  {str(bound):>14}  {str(ratio):>8}  {str(mn):>8}  {str(mx):>8}")

    return all_results


def plot_birthday_results(results: list[dict], out_path: str):
    """Generate birthday bound plot with theory overlay."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

        n_vals = [r["n_bits"] for r in results]
        means = [r.get("mean_evaluations", 0) for r in results]
        theory = [2 ** (n / 2) for n in n_vals]
        mins_ = [r.get("min_evals", 0) for r in results]
        maxs_ = [r.get("max_evals", 0) for r in results]

        fig, ax = plt.subplots(figsize=(9, 5))
        ax.set_facecolor("#0f172a")
        fig.patch.set_facecolor("#0a0e1a")
        ax.tick_params(colors="white")
        for spine in ax.spines.values():
            spine.set_edgecolor("#334155")

        ax.plot(n_vals, theory, "o--", color="#22d3ee", linewidth=2, label="Theory: 2^(n/2)", zorder=3)
        ax.plot(n_vals, means, "s-", color="#6366f1", linewidth=2, label="Empirical mean", zorder=4)
        ax.fill_between(n_vals, mins_, maxs_, alpha=0.18, color="#f472b6", label="Min-Max range")

        ax.set_yscale("log")
        ax.set_xlabel("n (hash output bits)", color="white", fontsize=12)
        ax.set_ylabel("Evaluations until collision (log scale)", color="white", fontsize=12)
        ax.set_title("PA#9: Birthday Attack — Empirical vs Theory", color="white", fontsize=14, pad=12)
        ax.legend(facecolor="#1e293b", edgecolor="#334155", labelcolor="white", fontsize=11)
        ax.grid(True, color="#1e293b", linewidth=0.7)
        plt.tight_layout()
        plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close()
        print(f"Plot saved to {out_path}")
    except ImportError:
        print("matplotlib not available — skipping plot generation")


def run_pa09_demo(num_trials: int = 100) -> dict:
    results = run_pa09_experiment(num_trials=num_trials)

    # Save JSON
    json_path = os.path.join(OUTPUT_DIR, "pa09_birthday_data.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nData saved to {json_path}")

    # Generate plot
    plot_path = os.path.join(OUTPUT_DIR, "pa09_birthday_plot.png")
    plot_birthday_results(results, plot_path)
    return {"results": results, "plot": plot_path, "data": json_path}


if __name__ == "__main__":
    run_pa09_demo(num_trials=100)
