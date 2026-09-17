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
import time
from pathlib import Path

from claude_agent_sdk import (query, ClaudeAgentOptions, tool,
                              create_sdk_mcp_server, AssistantMessage, TextBlock,
                              ResultMessage)
from sandbox import make_sandbox
from scope import Scope
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


async def hunt(scope: Scope, target: str, backend: str = "docker",
               max_turns: int = 40) -> dict:
    ok, reason = scope.allows(target)
    print(f"[scope] {target}: {'ALLOWED' if ok else 'REFUSED'} — {reason}")
    if not ok:
        raise SystemExit(f"Refused by scope guardrail: {reason}")

    import os
    os.environ["CTF_SANDBOX"] = backend
    workdir = (Path("bounty_runs") / f"{int(time.time())}").resolve()
    (workdir / "files").mkdir(parents=True, exist_ok=True)

    with make_sandbox(workdir / "files", network=True) as sb:
        opts = ClaudeAgentOptions(
            system_prompt=BOUNTY_SYS, mcp_servers={"ctf": _server(sb)},
            allowed_tools=["mcp__ctf__sandbox_bash"], max_turns=max_turns)
        task = (f"Authorized target: {target}\nProgram: {scope.program}\n"
                f"In-scope hosts: {', '.join(scope.in_scope)}\n"
                f"Rate limit: ~{scope.rate_limit_rps} req/s.\n\n"
                "Recon the target, then enumerate and safely confirm vulnerabilities. "
                "Summarize every finding at the end.")
        thoughts, turns, cost = [], 0, None
        async for msg in query(prompt=task, options=opts):
            if isinstance(msg, AssistantMessage):
                turns += 1
            if isinstance(msg, ResultMessage) and msg.total_cost_usd:
                cost = msg.total_cost_usd
            for b in getattr(msg, "content", []) or []:
                if isinstance(b, TextBlock):
                    thoughts.append({"t": time.time(), "kind": "thought", "text": b.text})
        trace = sorted(sb.actions + thoughts, key=lambda e: e["t"])

    save_audit(workdir / "audit.jsonl", trace)
    report = await generate_report(scope.program, target, trace)
    (workdir / "findings.md").write_text(report)
    row = {"time": time.time(), "program": scope.program, "target": target,
           "turns": turns, "cost_usd": cost, "report": str(workdir / "findings.md")}
    with open(METRICS, "a") as f:
        f.write(json.dumps(row) + "\n")
    print(f"[done] {turns} turns; findings -> {workdir/'findings.md'}")
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True, help="authorization/scope JSON file")
    ap.add_argument("--target", required=True, help="in-scope target URL")
    ap.add_argument("--backend", default="docker")
    ap.add_argument("--max-turns", type=int, default=40)
    args = ap.parse_args()
    asyncio.run(hunt(Scope.load(args.scope), args.target, args.backend, args.max_turns))


if __name__ == "__main__":
    main()
