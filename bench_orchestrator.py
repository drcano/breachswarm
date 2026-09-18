"""A/B: single-agent baseline (solver.solve) vs multi-agent orchestrator on the SAME
chained target, same flag scoring, same sandbox/RAG. Answers whether the orchestrator
earns its overhead. Honest head-to-head for docs/OVERNIGHT.md.

Usage: ./.venv/bin/python bench_orchestrator.py --app boss_app.py --n 2 --flag 'flag{...}'
Stands up targets/<app> in docker, runs N of each mode, writes results/orchestrator_ab.jsonl.
"""
from __future__ import annotations

import argparse, asyncio, json, os, subprocess, time
from pathlib import Path

os.environ["CTF_SANDBOX"] = "docker"

from solver import Challenge, solve
from orchestrator import solve_chain
from stateful import solve_stateful

FLAGS = {  # known real flags for the built-in chained targets
    "boss_app.py": "flag{f0rtr3ss_ch41n_5sti_after_ssrf_pwn}",
    "chain_app.py": "flag{c1_ssrf_metadata_to_internal_admin}",
    "gauntlet_app.py": "flag{g4untl3t_1dor_nosql_jwt_ssrf_rce_cha1n}",
}
PROMPTS = {
    "boss_app.py": ("Authorized assessment of the Fortress API at {url} . It is a "
        "hardened multi-stage target — no single request wins; each defense unlocks "
        "the next. Chain the flaws and recover the real flag (beware decoys)."),
    "chain_app.py": ("Authorized assessment of a link-preview service at {url} (it "
        "fetches URLs to generate previews). Chain the flaw(s) to recover the flag. "
        "A single request will not be enough."),
    "gauntlet_app.py": ("Authorized assessment of the Gauntlet API at {url} . It is a "
        "deep multi-stage target — each defense unlocks the next. Chain the flaws end "
        "to end and recover the real flag (beware decoys)."),
}


def _up(app: str) -> tuple[str, str]:
    subprocess.run(["docker", "build", "-q", "-t", "vuln-target:latest", "targets/"],
                   check=True, capture_output=True)
    cname = f"ab-{app.replace('.py','').replace('_','-')}"
    subprocess.run(["docker", "rm", "-f", cname], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--rm", "--name", cname,
                    "-e", f"APP={app}", "vuln-target:latest"], check=True, capture_output=True)
    time.sleep(3)
    ip = subprocess.check_output(
        ["docker", "inspect", "-f",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cname]).decode().strip()
    return cname, f"http://{ip}:5000/"


async def _baseline(name, prompt, flag, wd, max_turns=40) -> dict:
    # workdir = wd/files (sandbox mount, kept clean); outdir = wd (audit/writeup persist
    # for post-hoc diagnosis of failures — see the /debug decoy loop we caught).
    ch = Challenge(name=name, category="Web Exploitation", prompt=prompt,
                   workdir=str(Path(wd) / "files"), outdir=wd,
                   flag_pattern=r"flag\{[^}\s]+\}", real_flag=flag)
    r = await solve(ch, max_turns=max_turns, retries=0)
    return {"mode": "baseline", "name": name, "solved": r.solved, "flag": r.flag,
            "turns": r.turns, "cost_usd": r.cost_usd, "duration_s": r.duration_s,
            "cost_sdk_usd": r.cost_sdk_usd, "tokens": r.tokens}


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", default="boss_app.py")
    ap.add_argument("--n", type=int, default=2, help="runs per mode")
    ap.add_argument("--flag", default=None)
    ap.add_argument("--modes", default="baseline,orchestrator")
    ap.add_argument("--orch-turns", type=int, default=24, help="orchestrator turn cap")
    ap.add_argument("--spec-turns", type=int, default=16, help="per-delegation turn cap")
    ap.add_argument("--base-turns", type=int, default=40, help="baseline turn cap")
    ap.add_argument("-o", default="results/orchestrator_ab.jsonl")
    args = ap.parse_args()
    flag = args.flag or FLAGS.get(args.app)
    prompt_t = PROMPTS.get(args.app, "Authorized assessment of {url} . Recover the flag.")
    modes = args.modes.split(",")

    cname, url = _up(args.app)
    print(f"[*] {args.app} live at {url}")
    prompt = prompt_t.format(url=url)
    rows = []
    try:
        for i in range(args.n):
            for mode in modes:
                tag = f"{args.app}-{mode}-{i+1}".replace(".py", "")
                wd = str((Path("results/ab_traces") / tag).resolve())
                (Path(wd) / "files").mkdir(parents=True, exist_ok=True)
                (Path(wd) / "files" / "note.txt").write_text("web target; no local files\n")
                sbwd = str(Path(wd) / "files")   # sandbox mount (clean); traces -> wd
                if True:
                    print(f"[run] {tag} ...", flush=True)
                    t = time.time()
                    try:
                        if mode == "baseline":
                            row = await _baseline(tag, prompt, flag, wd, args.base_turns)
                        elif mode == "stateful":
                            row = await solve_stateful(tag, prompt, sbwd, real_flag=flag,
                                                       max_turns=args.base_turns)
                        else:
                            row = await solve_chain(tag, prompt, sbwd, real_flag=flag,
                                                    orch_max_turns=args.orch_turns,
                                                    spec_max_turns=args.spec_turns)
                    except Exception as e:
                        # solver.solve() RAISES on max_turns (SDK ResultError). That's a
                        # legitimate non-solve within budget, not an infra error -> record
                        # solved=False; only true infra errors get an `error` field
                        # (excluded from rate later).
                        msg = str(e)
                        cap = "maximum number of turns" in msg.lower()
                        cap_turns = args.base_turns if mode == "baseline" else args.orch_turns
                        row = {"mode": mode, "name": tag, "solved": False, "flag": None,
                               "turns": cap_turns if cap else None, "cost_usd": None,
                               "duration_s": round(time.time() - t, 1),
                               "error": None if cap else msg[:180]}
                    row.update({"app": args.app, "iter": i + 1, "time": time.time()})
                    rows.append(row)
                    print(f"      -> solved={row['solved']} turns={row.get('turns')} "
                          f"cost=${row.get('cost_usd')} {row.get('duration_s')}s "
                          f"flag={row.get('flag')}", flush=True)
                    with open(args.o, "a") as f:
                        f.write(json.dumps(row) + "\n")
    finally:
        subprocess.run(["docker", "rm", "-f", cname], capture_output=True)

    # summary
    def agg(mode):
        m = [r for r in rows if r["mode"] == mode]
        if not m:
            return None
        n = len(m)
        return {"n": n, "solved": sum(r["solved"] for r in m),
                "avg_turns": round(sum(r.get("turns") or 0 for r in m) / n, 1),
                "avg_cost": round(sum(r.get("cost_usd") or 0 for r in m) / n, 3),
                "avg_s": round(sum(r.get("duration_s") or 0 for r in m) / n, 1)}
    print("\n=== A/B SUMMARY ===")
    for mode in modes:
        print(f"  {mode:12} {agg(mode)}")


if __name__ == "__main__":
    asyncio.run(main())
