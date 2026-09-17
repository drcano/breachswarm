"""Batch runner: solve a folder of challenges, log results, print solve rate.

Challenge folder layout (one dir per challenge):
  <dir>/challenge.json   -> {name, category, prompt/description, flag, flag_pattern?}
  <dir>/*                -> the files handed to the solver (mounted at /work)

`flag` is the ground-truth flag for scoring (NYU CTF Bench provides it); omit it
for a live CTF and solves fall back to flag-shape matching.
"""
import argparse
import asyncio
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from solver import Challenge, solve


def load(dir_: Path) -> Challenge:
    meta = json.loads((dir_ / "challenge.json").read_text())
    return Challenge(
        name=meta.get("name", dir_.name),
        category=meta.get("category"),
        prompt=meta.get("prompt") or meta.get("description", ""),
        workdir=str(dir_.resolve()),
        flag_pattern=meta.get("flag_pattern"),
        real_flag=meta.get("flag"),
    )


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="folder of challenge subdirs")
    ap.add_argument("-o", "--out", default="results.jsonl")
    args = ap.parse_args()

    dirs = sorted(p for p in Path(args.root).iterdir()
                  if (p / "challenge.json").exists())
    results = []
    with open(args.out, "w") as f:
        for d in dirs:
            r = await solve(load(d))
            results.append(r)
            f.write(json.dumps(asdict(r)) + "\n")
            f.flush()  # crash-safe: keep partial results
            cost = f" ${r.cost_usd:.3f}" if r.cost_usd else ""
            print(f"[{'SOLVED' if r.solved else 'fail  '}] {r.name} "
                  f"({r.specialist}, {r.turns} turns{cost}) {r.flag or ''}")

    n = len(results)
    solved = sum(r.solved for r in results)
    print(f"\n{solved}/{n} solved ({solved / n:.0%})" if n else "no challenges found")
    by_cat = Counter(r.specialist for r in results if r.solved)
    for cat, c in by_cat.most_common():
        print(f"  {cat}: {c}")


if __name__ == "__main__":
    asyncio.run(main())
