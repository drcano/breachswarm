"""Authorized bug-bounty / security-research runner.

Refuses to run unless a scope file authorizes the target (scope.py). Then runs the
web specialist against the in-scope host, captures a full audit trail, generates a
findings report, and appends a row to the success-metrics ledger.

Usage:
  ./.venv/bin/python bounty.py --scope scope.json --target https://app.example.com
"""
from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import time
import uuid
from pathlib import Path

from claude_agent_sdk import (query, ClaudeAgentOptions, tool,
                              create_sdk_mcp_server, AssistantMessage, TextBlock,
                              ResultMessage)
from sandbox import make_sandbox
from scope import Scope
from config import MODEL
from specialists import SPECIALISTS
from writeup import save_audit
from report import generate_report

METRICS = "bounty_metrics.jsonl"

BOUNTY_SYS = SPECIALISTS["web"] + (
    "\n\nBUG-BOUNTY MODE. You are testing an AUTHORIZED, in-scope target only. "
    "Rules of engagement: stay strictly on the target host(s) named in the task — "
    "never pivot to any other host; respect the stated rate limit; perform NO "
    "destructive actions (no data deletion, no DoS, no account lockouts). Enumerate "
    "and safely confirm real vulnerabilities (OWASP classes). For each finding record: "
    "class, endpoint, a minimal proof-of-concept request, observed evidence, impact, "
    "and remediation."
)


def _server(sb):
    @tool("sandbox_bash", "Run a shell command in the (network-enabled) sandbox",
          {"command": str})
    async def sandbox_bash(args):
        return {"content": [{"type": "text", "text": sb.bash(args["command"])}]}
    return create_sdk_mcp_server(name="ctf", version="1.0", tools=[sandbox_bash])


def _start_enforcement(scope_path: str, image: str = "ctf-agent:full"):
    """No-bypass egress: internal-only network + an allowlisting proxy that is the
    agent's ONLY route out. Returns (network_name, proxy_url, cleanup)."""
    net = f"bnet_{uuid.uuid4().hex[:8]}"
    proxy = f"bproxy_{uuid.uuid4().hex[:8]}"
    subprocess.run(["docker", "network", "create", "--internal", net],
                   check=True, capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", proxy, "--network", net,
                    "-v", f"{Path.cwd()}:/work", "-w", "/work", image,
                    "python3", "egress_proxy.py", "--scope", f"/work/{scope_path}",
                    "--port", "8888"], check=True, capture_output=True)
    subprocess.run(["docker", "network", "connect", "bridge", proxy],
                   check=True, capture_output=True)  # only the proxy gets internet
    time.sleep(3)
    ip = subprocess.check_output(
        ["docker", "inspect", "-f",
         '{{(index .NetworkSettings.Networks "' + net + '").IPAddress}}', proxy]
    ).decode().strip()

    def cleanup():
        subprocess.run(["docker", "rm", "-f", proxy], capture_output=True)
        subprocess.run(["docker", "network", "rm", net], capture_output=True)
    print(f"[enforce] internal net {net}, egress only via proxy {ip}:8888")
    return net, f"http://{ip}:8888", cleanup


async def hunt(scope: Scope, target: str, backend: str = "docker",
               max_turns: int = 40, scope_path: str | None = None,
               enforce: bool = False, parallel_recon: bool = False) -> dict:
    ok, reason = scope.allows(target)
    print(f"[scope] {target}: {'ALLOWED' if ok else 'REFUSED'} — {reason}")
    if not ok:
        raise SystemExit(f"Refused by scope guardrail: {reason}")

    import os
    os.environ["CTF_SANDBOX"] = backend
    workdir = (Path("bounty_runs") / f"{int(time.time())}").resolve()
    (workdir / "files").mkdir(parents=True, exist_ok=True)

    net_name = proxy_url = None
    cleanup = lambda: None
    if enforce:
        net_name, proxy_url, cleanup = _start_enforcement(scope_path)

    try:
        with make_sandbox(workdir / "files", network=True,
                          network_name=net_name, proxy_url=proxy_url) as sb:
            opts = ClaudeAgentOptions(
                system_prompt=BOUNTY_SYS, mcp_servers={"ctf": _server(sb)},
                allowed_tools=["mcp__ctf__sandbox_bash"], max_turns=max_turns, model=MODEL)
            recon_turns, recon_cost, recon_map = 0, 0.0, ""
            usages = []  # raw ResultMessage.model_usage dicts for token-based costing
            if parallel_recon:
                from recon_agents import parallel_recon as _precon
                ctx = (f"Program: {scope.program}. In-scope: {', '.join(scope.in_scope)}. "
                       f"Rate limit ~{scope.rate_limit_rps} req/s.")
                pr = await _precon(sb, target, ctx)
                recon_turns, recon_cost, recon_map = pr["turns"], pr["cost"], pr["map"]
                usages.extend(pr.get("usages", []))
                print(f"[parallel-recon] {recon_turns} turns, ${recon_cost}, "
                      f"{pr['wall_s']}s across {len(pr['areas'])} subagents")
            task = (f"Authorized target: {target}\nProgram: {scope.program}\n"
                    f"In-scope hosts: {', '.join(scope.in_scope)}\n"
                    f"Rate limit: ~{scope.rate_limit_rps} req/s.\n\n"
                    + (f"A recon team already mapped the attack surface — start from "
                       f"this and go straight to exploitation, don't re-enumerate:\n"
                       f"{recon_map}\n\n" if recon_map else "")
                    + "Recon the target, then enumerate and safely confirm vulnerabilities. "
                    "Summarize every finding at the end.")
            thoughts, turns, cost = [], 0, None
            async for msg in query(prompt=task, options=opts):
                if isinstance(msg, AssistantMessage):
                    turns += 1
                if isinstance(msg, ResultMessage):
                    if msg.total_cost_usd:
                        cost = msg.total_cost_usd
                    if msg.model_usage:
                        usages.append(msg.model_usage)
                for b in getattr(msg, "content", []) or []:
                    if isinstance(b, TextBlock):
                        thoughts.append({"t": time.time(), "kind": "thought", "text": b.text})
            trace = sorted(sb.actions + thoughts, key=lambda e: e["t"])
    finally:
        cleanup()

    save_audit(workdir / "audit.jsonl", trace)
    report = await generate_report(scope.program, target, trace)
    (workdir / "findings.md").write_text(report)
    # wall-clock speed of the assessment, from the trace timestamps
    ts = [e["t"] for e in trace if "t" in e]
    duration_s = round(ts[-1] - ts[0], 1) if len(ts) > 1 else None
    total_turns = turns + recon_turns
    total_cost = (cost or 0) + recon_cost if (cost or recon_cost) else None
    from pricing import summarize
    usage = summarize(usages)  # token-based, self-verifiable cost from raw token counts
    row = {"time": time.time(), "program": scope.program, "target": target,
           "turns": total_turns, "cost_usd": total_cost, "duration_s": duration_s,
           "parallel_recon": parallel_recon,
           "recon_turns": recon_turns, "exploit_turns": turns,
           "tokens": usage["tokens"],
           "cost_recomputed_usd": usage["cost_recomputed_usd"],
           "cost_sdk_usd": usage["cost_sdk_usd"],
           "report": str(workdir / "findings.md")}
    with open(METRICS, "a") as f:
        f.write(json.dumps(row) + "\n")
    dur = f", {duration_s:.0f}s" if duration_s else ""
    split = f" ({recon_turns} recon + {turns} exploit)" if parallel_recon else ""
    tk = usage["tokens"]
    print(f"[done] {total_turns} turns{split}{dur}; "
          f"tokens in/out {tk['input']}/{tk['output']} "
          f"(+{tk['cache_read']} cache); cost ${usage['cost_recomputed_usd']} "
          f"recomputed / ${usage['cost_sdk_usd']} sdk; findings -> {workdir/'findings.md'}")
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True, help="authorization/scope JSON file")
    ap.add_argument("--target", required=True, help="in-scope target URL")
    ap.add_argument("--backend", default="docker")
    ap.add_argument("--max-turns", type=int, default=40)
    ap.add_argument("--enforce", action="store_true",
                    help="no-bypass egress: run the agent on an internal-only network "
                         "whose sole route out is the scope-allowlisting proxy")
    ap.add_argument("--parallel-recon", action="store_true",
                    help="fan out read-only recon subagents to map the surface first, "
                         "then exploit from that map (helps broad targets)")
    args = ap.parse_args()
    asyncio.run(hunt(Scope.load(args.scope), args.target, args.backend,
                     args.max_turns, scope_path=args.scope, enforce=args.enforce,
                     parallel_recon=args.parallel_recon))


if __name__ == "__main__":
    main()
