"""Engagement-aware adversary-emulation runner — ties the whole containment model into ONE
command: authorized (RoE-gated, expiring) + contained (network-enforced RoE) + accountable
(tamper-evident audit) + safe (no-destruction rail) + a BLUE-TEAM SCORECARD at the end.

Usage:
  ./.venv/bin/python redteam.py --engagement engagement.json --target http://<in-scope> [--enforce]

Refuses to run unless the engagement authorizes the target AND is currently active (window +
kill switch). Every action is recorded to a hash-chained audit log and tagged with its ATT&CK
technique; the run ends with a findings report AND a detection scorecard (what the controls
caught vs missed).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import time
from pathlib import Path

from claude_agent_sdk import (query, ClaudeAgentOptions, tool, create_sdk_mcp_server,
                              AssistantMessage, TextBlock, ResultMessage)
from config import MODEL
from engagement import Engagement
from audit_chain import AuditChain, verify as audit_verify
from techniques import classify, outcome_from, scorecard, render as render_scorecard
from safety import guard_destructive, announce
from bounty import BOUNTY_SYS, _start_enforcement
from solver import _knowledge_server, _stall_nudge, _decoy_nudge, _waf_nudge, _rate_nudge
from sandbox import make_sandbox
from report import generate_report
from writeup import save_audit


def _status(out: str):
    m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", out or "")
    return int(m.group(1)) if m else (200 if (out or "").strip() else None)


def _server(sb, audit: AuditChain, events: list, fp: dict, destructive_ok: bool):
    """Sandbox tool that (1) blocks destruction, (2) records every action to the tamper-
    evident chain tagged with ATT&CK, (3) feeds the scorecard, (4) keeps the stealth nudges."""
    stall = {"window": [], "cooldown": 0}

    @tool("sandbox_bash", "Run a shell command in the network-contained sandbox", {"command": str})
    async def sandbox_bash(args):
        cmd = args.get("command", "")
        allowed, why = guard_destructive(cmd, destructive_ok)
        if not allowed:
            fp["destructive_blocks"] += 1
            audit.record("blocked", command=cmd[:500], reason="destructive")
            return {"content": [{"type": "text", "text": why}]}
        out = sb.bash(cmd)
        fp["tool_calls"] += 1
        status = _status(out)
        blocked, success = outcome_from(status, out)
        techs = [t[0] for t in classify(cmd)]
        audit.record("request", command=cmd[:500], status=status, blocked=blocked,
                     success=success, techniques=techs)
        if techs:
            events.append({"payload": cmd, "blocked": blocked, "success": success})
        return {"content": [{"type": "text", "text": out + _stall_nudge(out, stall)
                             + _decoy_nudge(out) + _waf_nudge(out, stall)
                             + _rate_nudge(out, stall)}]}

    return create_sdk_mcp_server(name="ctf", version="1.0", tools=[sandbox_bash])


async def run(eng: Engagement, eng_path: str, target: str, enforce: bool = False,
              max_turns: int = 40) -> dict:
    ok, why = eng.allows_target(target)
    print(f"[engagement] target {target}: {'ALLOWED' if ok else 'REFUSED'} — {why}")
    if not ok:
        raise SystemExit(f"Refused by RoE: {why}")
    print(eng.preflight())

    os.environ["CTF_SANDBOX"] = "docker"
    workdir = (Path("redteam_runs") / f"{int(time.time())}").resolve()
    (workdir / "files").mkdir(parents=True, exist_ok=True)
    audit = AuditChain(str(workdir / "audit_chain.jsonl"))
    audit.record("start", program=eng.scope.program, operator=eng.operator, target=target)
    _meta = {"program": eng.scope.program, "operator": eng.operator, "target": target}
    announce(eng.deconfliction, "start", f"{eng.scope.program} vs {target} (op={eng.operator})", _meta)

    net = proxy_url = None
    cleanup = lambda: None
    if enforce:
        net, proxy_url, cleanup = _start_enforcement(eng_path, engagement=True)

    events, fp = [], {"tool_calls": 0, "destructive_blocks": 0}
    turns, trace = 0, []
    try:
        with make_sandbox(workdir / "files", network=True,
                          network_name=net, proxy_url=proxy_url) as sb:
            srv = _server(sb, audit, events, fp, eng.destructive)
            opts = ClaudeAgentOptions(
                system_prompt=BOUNTY_SYS,
                mcp_servers={"ctf": srv, "kb": _knowledge_server()},
                allowed_tools=["mcp__ctf__sandbox_bash", "mcp__kb__search_knowledge"],
                max_turns=max_turns, model=MODEL)
            task = (f"AUTHORIZED adversary emulation. Target: {target}\n"
                    f"Program: {eng.scope.program}. In-scope: {', '.join(eng.scope.in_scope)}. "
                    f"Rate ~{eng.scope.rate_limit_rps}/s.\n"
                    "Recon, then enumerate and safely CONFIRM vulnerabilities with a minimal "
                    "proof. Prefer evaded, low-signature payloads. Never destroy data. "
                    "Summarize every finding at the end.")
            thoughts = []
            async for msg in query(prompt=task, options=opts):
                if isinstance(msg, AssistantMessage):
                    turns += 1
                for b in getattr(msg, "content", []) or []:
                    if isinstance(b, TextBlock):
                        thoughts.append({"t": time.time(), "kind": "thought", "text": b.text})
            trace = sorted(sb.actions + thoughts, key=lambda e: e["t"])
    except Exception as e:
        print(f"[run stopped: {e}]")
    finally:
        cleanup()

    audit.record("stop", turns=turns, actions=fp["tool_calls"],
                 destructive_blocks=fp["destructive_blocks"])

    sc = scorecard(events)
    save_audit(workdir / "audit.jsonl", trace)
    chain_ok, msg = audit_verify(str(workdir / "audit_chain.jsonl"))
    gaps = sorted(tid for tid, r in sc.items() if r["detection_gap"])
    (workdir / "findings.md").write_text(await generate_report(eng.scope.program, target, trace))
    (workdir / "scorecard.md").write_text(
        f"# Blue-team detection scorecard — {eng.scope.program}\n\n"
        f"Target: `{target}` · actions: {fp['tool_calls']} · "
        f"destructive blocked: {fp['destructive_blocks']} · audit: "
        f"{'VERIFIED' if chain_ok else 'TAMPERED'}\n\n" + render_scorecard(sc))
    # machine-readable, for SIEM / dashboard ingestion
    (workdir / "scorecard.json").write_text(json.dumps({
        "program": eng.scope.program, "target": target, "operator": eng.operator,
        "ts": round(time.time()), "turns": turns, "actions": fp["tool_calls"],
        "destructive_blocked": fp["destructive_blocks"], "audit_verified": chain_ok,
        "detection_gaps": gaps, "gap_count": len(gaps), "techniques": sc}, indent=2, default=str))
    announce(eng.deconfliction, "stop",
             f"{turns} turns, {fp['tool_calls']} actions, {len(gaps)} detection gaps",
             {**_meta, "detection_gaps": gaps, "audit_verified": chain_ok})
    print(f"[audit] {msg} — chain {'VERIFIED' if chain_ok else 'TAMPERED!'}")
    print(f"[done] {turns} turns; {fp['tool_calls']} actions "
          f"({fp['destructive_blocks']} destructive blocked); "
          f"findings -> {workdir/'findings.md'}; scorecard -> {workdir/'scorecard.md'}")
    print("\n" + render_scorecard(sc))
    return {"workdir": str(workdir), "turns": turns, "events": len(events),
            "audit_ok": chain_ok, "scorecard": sc}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engagement", required=True, help="engagement (RoE) JSON")
    ap.add_argument("--target", required=True, help="in-scope target URL")
    ap.add_argument("--enforce", action="store_true",
                    help="network containment: internal-only net + RoE-enforcing egress proxy")
    ap.add_argument("--max-turns", type=int, default=40)
    args = ap.parse_args()
    eng = Engagement.load(args.engagement)
    asyncio.run(run(eng, args.engagement, args.target, args.enforce, args.max_turns))


if __name__ == "__main__":
    main()
