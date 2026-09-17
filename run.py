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

from solver import Challenge, Result, solve
from specialists import route


def load(dir_: Path) -> Challenge:
    meta = json.loads((dir_ / "challenge.json").read_text())
    # Agent sees files/ only (if present); metadata + outputs live in the parent,
    # so the gold flag in challenge.json is never in the sandbox.
    files = dir_ / "files"
    workdir = files if files.is_dir() else dir_
    return Challenge(
        name=meta.get("name", dir_.name),
        category=meta.get("category"),
        prompt=meta.get("prompt") or meta.get("description", ""),
        workdir=str(workdir.resolve()),
        outdir=str(dir_.resolve()),
        flag_pattern=meta.get("flag_pattern"),
        real_flag=meta.get("flag"),
    )


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="folder of challenge subdirs")
    ap.add_argument("-o", "--out", default="results.jsonl")
    ap.add_argument("--limit", type=int, help="max challenges to run")
    ap.add_argument("--category", help="only run challenges routed to this specialist "
                    "(crypto/rev/pwn/web/forensics/misc)")
    ap.add_argument("--per-category", type=int, help="cap challenges per specialist "
                    "(representative sampling across categories)")
    ap.add_argument("--max-turns", type=int, default=40,
                    help="cap agent turns per challenge (cost control)")
    ap.add_argument("--concurrency", type=int, default=4,
                    help="challenges to solve in parallel (wallclock speedup)")
    args = ap.parse_args()

    dirs = [p for p in sorted(Path(args.root).iterdir())
            if (p / "challenge.json").exists()]
    # filter/sample before running (cost control)
    picked, seen = [], Counter()
    for d in dirs:
        spec = route(json.loads((d / "challenge.json").read_text()).get("category"))
        if args.category and spec != args.category:
            continue
        if args.per_category and seen[spec] >= args.per_category:
            continue
        seen[spec] += 1
        picked.append(d)
        if args.limit and len(picked) >= args.limit:
            break
    dirs = picked
    sem = asyncio.Semaphore(max(1, args.concurrency))

    async def run_one(d):
        ch = load(d)
        async with sem:  # bound parallel solves (containers + LLM rate limits)
            try:
                return await solve(ch, max_turns=args.max_turns)
            except Exception as e:  # one bad challenge must not kill the batch
                print(f"[ERROR ] {ch.name}: {type(e).__name__}: {str(e)[:120]}")
                return Result(ch.name, route(ch.category), False, False, None, 0, None)

    results = []
    tasks = [asyncio.create_task(run_one(d)) for d in dirs]
    with open(args.out, "w") as f:
        for coro in asyncio.as_completed(tasks):  # write as each finishes
            r = await coro
            results.append(r)
            f.write(json.dumps(asdict(r)) + "\n")
            f.flush()  # crash-safe: keep partial results
            cost = f" ${r.cost_usd:.3f}" if r.cost_usd else ""
            tag = "SOLVED" if r.solved else ("NEAR  " if r.near_miss else "fail  ")
            print(f"[{tag}] {r.name} "
                  f"({r.specialist}, {r.turns} turns{cost}) {r.flag or ''}")

    n = len(results)
    solved = sum(r.solved for r in results)
    near = sum(r.near_miss for r in results)
    if not n:
        print("no challenges found"); return
    print(f"\n{solved}/{n} solved strict ({solved / n:.0%}); "
          f"+{near} near-miss (cracked, mis-formatted) = {solved + near}/{n} "
          f"({(solved + near) / n:.0%}) effective")
    by_cat = Counter()
    for r in results:
        by_cat[r.specialist]  # ensure key
        if r.solved:
            by_cat[r.specialist] += 1
    for cat in sorted(by_cat):
        tot = sum(1 for r in results if r.specialist == cat)
        s = sum(1 for r in results if r.specialist == cat and r.solved)
        nm = sum(1 for r in results if r.specialist == cat and r.near_miss)
        print(f"  {cat}: {s}/{tot} strict (+{nm} near)")


if __name__ == "__main__":
    asyncio.run(main())
