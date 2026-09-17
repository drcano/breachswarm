"""Orchestrator + specialist runner + verifier.

Flow per challenge:
  route(category) -> pick specialist prompt
  spin up Sandbox  -> give the specialist a sandbox_bash tool
  run the Agent SDK loop, watching every tool result for a flag
  flag found -> stop early (auto-terminate); score with flag.is_correct

The Agent SDK provides the agent loop and MCP plumbing; the composition
(routing, per-challenge sandbox, flag-gated termination, scoring) is ours.

NB: pin claude-agent-sdk and verify these imports against the installed version
— the SDK's surface moves. This targets the documented @tool /
create_sdk_mcp_server / query API.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from claude_agent_sdk import (
    query, ClaudeAgentOptions, tool, create_sdk_mcp_server,
)

from flag import find_flag, is_correct
from sandbox import Sandbox
from specialists import SPECIALISTS, route
from writeup import generate, save_audit


@dataclass
class Challenge:
    name: str
    category: str | None
    prompt: str            # the challenge description shown to solvers
    workdir: str           # host dir with the challenge files, mounted at /work
    flag_pattern: str | None = None
    real_flag: str | None = None   # set by the benchmark for scoring; None in live CTF


@dataclass
class Result:
    name: str
    specialist: str
    solved: bool
    flag: str | None
    turns: int
    writeup_path: str | None = None
    audit_path: str | None = None


def _sandbox_server(sb: Sandbox):
    """Build an in-process MCP server exposing this challenge's sandbox as a tool."""
    @tool("sandbox_bash", "Run a shell command inside the challenge sandbox",
          {"command": str})
    async def sandbox_bash(args):
        out = sb.bash(args["command"])
        return {"content": [{"type": "text", "text": out}]}

    return create_sdk_mcp_server(name="ctf", version="0.1", tools=[sandbox_bash])


async def solve(ch: Challenge, max_turns: int = 40) -> Result:
    spec = route(ch.category)
    with Sandbox(ch.workdir) as sb:
        options = ClaudeAgentOptions(
            system_prompt=SPECIALISTS[spec],
            mcp_servers={"ctf": _sandbox_server(sb)},
            allowed_tools=["mcp__ctf__sandbox_bash"],
            max_turns=max_turns,
        )
        task = f"Challenge: {ch.name}\n\n{ch.prompt}\n\nFiles are in /work. Find the flag."

        found, turns, thoughts = None, 0, []
        async for msg in query(prompt=task, options=options):
            turns += 1
            # Scan every text block (assistant reasoning + tool output) for a flag,
            # and keep the reasoning for the audit trace / writeup.
            for block in getattr(msg, "content", []) or []:
                text = getattr(block, "text", None)
                if not text:
                    continue
                thoughts.append({"t": time.time(), "kind": "thought", "text": text})
                if hit := find_flag(text, ch.flag_pattern):
                    found = hit
            if found:
                break  # auto-terminate: stop burning turns once the flag appears

        # Merge command log + reasoning into one chronological trace.
        trace = sorted(sb.actions + thoughts, key=lambda e: e["t"])
        if found:
            trace.append({"t": time.time(), "kind": "flag", "text": found})

    solved = is_correct(found, ch.real_flag)
    out = Path(ch.workdir)
    audit_path = out / "audit.jsonl"
    writeup_path = out / "writeup.md"
    save_audit(audit_path, trace)
    writeup_path.write_text(await generate(ch.name, ch.prompt, trace, solved, found))
    return Result(ch.name, spec, solved, found, turns,
                  str(writeup_path), str(audit_path))
