"""Summarize the orchestrator A/B ledger into a per-target, per-mode comparison table
(solve rate, avg turns, avg cost, avg wall-clock) for docs/OVERNIGHT.md. Read-only.

Usage: ./.venv/bin/python analyze_ab.py [results/orchestrator_ab.jsonl ...]
"""
from __future__ import annotations

import json, sys
from collections import defaultdict


def load(paths):
    rows = []
    for p in paths:
        try:
            with open(p) as f:
                rows += [json.loads(l) for l in f if l.strip()]
        except FileNotFoundError:
            pass
    return rows


def summarize(rows):
    g = defaultdict(list)
    for r in rows:
        g[(r.get("app", "?"), r["mode"])].append(r)
    out = {}
    for (app, mode), rs in sorted(g.items()):
        n = len(rs)
        def avg(k):
            vals = [r.get(k) or 0 for r in rs]
            return round(sum(vals) / n, 2) if n else 0
        # prefer token-based sdk cost when present, else the SDK total_cost_usd
        costs = [(r.get("cost_sdk_usd") or r.get("cost_usd") or 0) for r in rs]
        out[(app, mode)] = {
            "n": n, "solved": sum(1 for r in rs if r.get("solved")),
            "avg_turns": avg("turns"), "avg_cost": round(sum(costs) / n, 3) if n else 0,
            "avg_s": avg("duration_s")}
    return out


def table(summary) -> str:
    lines = ["| target | mode | solved | avg turns | avg cost $ | avg wall s |",
             "|---|---|---|---|---|---|"]
    for (app, mode), s in summary.items():
        lines.append(f"| {app} | {mode} | {s['solved']}/{s['n']} | {s['avg_turns']} | "
                     f"{s['avg_cost']} | {s['avg_s']} |")
    return "\n".join(lines)


def main():
    paths = sys.argv[1:] or ["results/orchestrator_ab.jsonl"]
    rows = load(paths)
    if not rows:
        print("no rows yet"); return
    summ = summarize(rows)
    print(table(summ))
    # headline deltas baseline vs orchestrator, per target
    print()
    apps = sorted({a for a, _ in summ})
    for app in apps:
        b, o = summ.get((app, "baseline")), summ.get((app, "orchestrator"))
        if b and o:
            cx = round(o["avg_cost"] / b["avg_cost"], 1) if b["avg_cost"] else float("inf")
            tx = round(o["avg_turns"] / b["avg_turns"], 1) if b["avg_turns"] else float("inf")
            print(f"{app}: orchestrator vs baseline -> solve {o['solved']}/{o['n']} vs "
                  f"{b['solved']}/{b['n']}; {cx}x cost, {tx}x turns, "
                  f"{round(o['avg_s']/max(b['avg_s'],1),1)}x wall")


if __name__ == "__main__":
    main()
