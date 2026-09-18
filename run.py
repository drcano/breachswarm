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
    ap.add_argument("--retries", type=int, default=0,
                    help="extra attempts per challenge on failure (recovers near-misses)")
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
    # Shared backoff clock: when any worker hits an API rate/session limit, all
    # workers wait until this monotonic time before trying again, so a limit pauses
    # the batch instead of force-failing every remaining task (which polluted a
    # whole run at task 43 before this existed).
    import time
    RATE_HINTS = ("rate limit", "rate_limit", "session limit", "overloaded",
                  "429", "resets", "too many requests")
    gate = {"resume_at": 0.0}

    async def run_one(d):
        ch = load(d)
        async with sem:  # bound parallel solves (containers + LLM rate limits)
            for attempt in range(6):
                wait = gate["resume_at"] - time.monotonic()
                if wait > 0:
                    await asyncio.sleep(wait)
                try:
                    return await solve(ch, max_turns=args.max_turns, retries=args.retries)
                except Exception as e:
                    msg = str(e).lower()
                    rate_limited = any(h in msg for h in RATE_HINTS)
                    if rate_limited and attempt < 5:
                        delay = min(300, 30 * 2 ** attempt)  # 30s→…→300s cap
                        gate["resume_at"] = max(gate["resume_at"],
                                                time.monotonic() + delay)
                        print(f"[backoff] {ch.name}: rate limit — pausing batch "
                              f"{delay}s (attempt {attempt + 1}/5)")
                        continue
                    # unrecoverable (or exhausted backoff): tag, don't score as a fail
                    tag = "rate-limited" if rate_limited else f"{type(e).__name__}: {str(e)[:100]}"
                    print(f"[ERROR ] {ch.name}: {tag}")
                    return Result(ch.name, route(ch.category), False, False, None,
                                  0, error=tag)

    results = []
    tasks = [asyncio.create_task(run_one(d)) for d in dirs]
    with open(args.out, "w") as f:
        for coro in asyncio.as_completed(tasks):  # write as each finishes
            r = await coro
            results.append(r)
            f.write(json.dumps(asdict(r)) + "\n")
            f.flush()  # crash-safe: keep partial results
            cost = f" ${r.cost_usd:.3f}" if r.cost_usd else ""
            dur = f" {r.duration_s:.0f}s" if r.duration_s else ""
            tag = "SOLVED" if r.solved else ("NEAR  " if r.near_miss else "fail  ")
            print(f"[{tag}] {r.name} "
                  f"({r.specialist}, {r.turns} turns{dur}{cost}) {r.flag or ''}")

    errored = [r for r in results if r.error]
    scored = [r for r in results if not r.error]  # rate-limited/errored don't count
    n = len(scored)
    solved = sum(r.solved for r in scored)
    near = sum(r.near_miss for r in scored)  # near_miss == correct flag, wrong case only
    if not n:
        print("no challenges scored" + (f" ({len(errored)} errored)" if errored else ""))
        return
    print(f"\n{solved}/{n} solved strict ({solved / n:.0%}); "
          f"{solved + near}/{n} case-insensitive ({(solved + near) / n:.0%}) "
          f"[+{near} correct-flag/wrong-case]")
    if errored:
        rl = sum(1 for r in errored if r.error == "rate-limited")
        print(f"excluded from scoring: {len(errored)} errored"
              f"{f' ({rl} rate-limited)' if rl else ''} — rerun these")
    ttf = sorted(r.time_to_flag_s for r in scored if r.solved and r.time_to_flag_s)
    if ttf:
        med = ttf[len(ttf) // 2]
        print(f"time-to-exploit (solved): fastest {ttf[0]:.0f}s · median {med:.0f}s · "
              f"slowest {ttf[-1]:.0f}s")
    by_cat = Counter()
    for r in scored:
        by_cat[r.specialist]  # ensure key
        if r.solved:
            by_cat[r.specialist] += 1
    for cat in sorted(by_cat):
        tot = sum(1 for r in scored if r.specialist == cat)
        s = sum(1 for r in scored if r.specialist == cat and r.solved)
        nm = sum(1 for r in scored if r.specialist == cat and r.near_miss)
        print(f"  {cat}: {s}/{tot} strict (+{nm} near)")


if __name__ == "__main__":
    asyncio.run(main())
