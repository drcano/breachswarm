"""Stateful single-agent solver — the cheap middle ground between the plain baseline
(implicit memory in one context) and the multi-agent orchestrator (expensive nested
sub-agents). ONE agent, one context, plus an explicit artifact blackboard it writes
discovered tokens/keys/URLs/roles to and sees echoed back — so chain state is tracked
deliberately instead of hoped-for. No nested agents, so ~baseline cost.

Purpose: isolate WHICH ingredient (if any) helps deep chains — explicit state vs multi-
agent delegation. Compared head-to-head in bench_orchestrator (mode=stateful). Kept only
if it wins.
"""
from __future__ import annotations

import time
from pathlib import Path

from claude_agent_sdk import (query, ClaudeAgentOptions, tool, create_sdk_mcp_server,
                              AssistantMessage, TextBlock, ResultMessage)
from config import MODEL
from flag import find_flag, is_correct
from specialists import SPECIALISTS
from solver import _sandbox_server, _knowledge_server, _block_text
from sandbox import make_sandbox
from recon import recon, brief_text

STATE_NOTE = (
    "\n\nCHAIN STATE: this is a multi-stage target — each stage's output (a token, key, "
    "credential, internal URL, or role) is the INPUT to the next. As soon as you recover "
    "such an artifact, call record_artifact(key,value) to save it; the blackboard is "
    "echoed back so you always have it. Before every new request ask: which known "
    "artifact unlocks this? A gate ('admin only', 'requires X') means X is your next "
    "objective, not a dead end."
)


def _state_server(blackboard):
    @tool("record_artifact",
          "Save a discovered artifact (token/key/credential/internal-url/role) so you "
          "reuse it in later chain stages.", {"key": str, "value": str})
    async def record_artifact(args):
        k, v = args.get("key", "").strip(), args.get("value", "").strip()
        if k:
            blackboard[k] = v
        return {"content": [{"type": "text", "text":
                f"blackboard: {blackboard}"}]}

    return create_sdk_mcp_server(name="state", version="1.0", tools=[record_artifact])


async def solve_stateful(name: str, prompt: str, workdir: str,
                         real_flag: str | None = None, max_turns: int = 40,
                         flag_pattern: str = r"flag\{[^}\s]+\}") -> dict:
    t0 = time.time()
    blackboard: dict[str, str] = {}
    turns, cost, usages, found = 0, 0.0, [], None
    with make_sandbox(workdir, network=True) as sb:
        brief = recon(sb, prompt)
        servers = {"ctf": _sandbox_server(sb), "kb": _knowledge_server(),
                   "state": _state_server(blackboard)}
        opts = ClaudeAgentOptions(
            system_prompt=SPECIALISTS["web"] + STATE_NOTE, mcp_servers=servers,
            allowed_tools=["mcp__ctf__sandbox_bash", "mcp__kb__search_knowledge",
                           "mcp__state__record_artifact"],
            max_turns=max_turns, model=MODEL)
        task = (f"Target: {name}\n\n{prompt}\n\n{brief_text(brief)}\n\n"
                "Chain the flaws end to end and find the flag.")
        try:
            async for msg in query(prompt=task, options=opts):
                if isinstance(msg, AssistantMessage):
                    turns += 1
                if isinstance(msg, ResultMessage):
                    if msg.total_cost_usd:
                        cost += msg.total_cost_usd
                    if msg.model_usage:
                        usages.append(msg.model_usage)
                for b in getattr(msg, "content", []) or []:
                    t = _block_text(b)
                    if t and (hit := find_flag(t, flag_pattern)):  # strict: avoid args{name}
                        found = hit
                if found:
                    break
        except Exception as e:
            print(f"[stateful stopped: {e}]")
    dur = round(time.time() - t0, 1)
    from pricing import summarize
    usage = summarize(usages)
    return {"mode": "stateful", "name": name, "solved": is_correct(found, real_flag),
            "flag": found, "turns": turns, "cost_usd": round(cost, 4),
            "duration_s": dur, "tokens": usage["tokens"],
            "cost_sdk_usd": usage["cost_sdk_usd"], "artifacts": dict(blackboard)}


if __name__ == "__main__":
    bb = {}
    s = _state_server(bb)
    assert "CHAIN STATE" in STATE_NOTE
    print("stateful.py ok")
