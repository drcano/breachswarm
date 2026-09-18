"""A/B harness: does parallel-recon help on a LARGE attack surface?

The first parallel-recon measurement used rest.vulnweb.com (a modest surface) once.
This runs the assessment N times per arm (parallel-recon OFF vs ON), interleaved,
against self-hosted OWASP Juice Shop — a genuinely broad target (dozens of REST
endpoints + SPA) where breadth should matter most. Recon subagents run on haiku
(cheap) so the fan-out doesn't dominate cost. Reports turn/cost/wall distributions
with a permutation p-value; token-based cost (pricing.py) makes the dollars
re-derivable.

Usage: CTF_SANDBOX=docker ./.venv/bin/python bench_recon.py --runs 4
"""
import argparse
import asyncio
import json
import statistics as st
import subprocess
import time
from pathlib import Path

from scope import Scope
from bounty import hunt
from bench_detector import perm_test


def sh(c: str) -> str:
    return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()


def start_juice() -> str:
    sh("docker rm -f juice")
    sh("docker run -d --rm --name juice bkimminich/juice-shop")
    time.sleep(15)  # Juice Shop is slow to boot
    ip = sh("docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}"
            "{{end}}' juice")
    json.dump({"program": "OWASP Juice Shop (own instance)", "authorized": True,
               "in_scope": [ip], "out_of_scope": [], "rate_limit_rps": 8.0,
               "notes": "self-hosted large-surface A/B target"},
              open("scope.juice.json", "w"), indent=2)
    return ip


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=4, help="runs PER arm")
    args = ap.parse_args()
    ip = start_juice()
    target = f"http://{ip}:3000/"
    print(f"[*] Juice Shop (large surface) at {target}")
    scope = Scope.load("scope.juice.json")

    rows = {"off": [], "on": []}
    order = ["off", "on"] * args.runs   # interleaved to balance drift
    for i, arm in enumerate(order, 1):
        r = await hunt(scope, target, backend="docker", max_turns=40,
                       scope_path="scope.juice.json", enforce=False,
                       parallel_recon=(arm == "on"))
        rows[arm].append(r)
        print(f"[{i}/{len(order)}] recon={arm:<3} total={r['turns']}t "
              f"(recon={r.get('recon_turns')} exploit={r.get('exploit_turns')}) "
              f"cost=${r.get('cost_recomputed_usd')} wall={r.get('duration_s')}s")
    sh("docker rm -f juice")

    Path("results").mkdir(exist_ok=True)
    json.dump(rows, open("results/recon_ab.json", "w"), indent=2, default=str)

    print("\n=== A/B: parallel-recon OFF vs ON on a large surface ===")
    def col(arm, k):
        return [x[k] for x in rows[arm] if isinstance(x.get(k), (int, float))]
    for k in ("turns", "cost_recomputed_usd", "duration_s"):
        off, on = col("off", k), col("on", k)
        if len(off) >= 2 and len(on) >= 2:
            p = perm_test(on, off)
            verdict = "significant" if p < 0.05 else "not significant (underpowered/no effect)"
            print(f"{k:22} off median {st.median(off):.1f} | on median {st.median(on):.1f}"
                  f" | Δ={st.median(on) - st.median(off):+.1f} | p={p:.3f} -> {verdict}")
        else:
            print(f"{k}: not enough successful runs")


if __name__ == "__main__":
    asyncio.run(main())
