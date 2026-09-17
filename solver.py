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
    AssistantMessage, TextBlock, ToolResultBlock, ResultMessage,
)

from flag import find_flag, is_correct
from recon import recon, brief_text
from sandbox import make_sandbox
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
    cost_usd: float | None = None
    writeup_path: str | None = None
    audit_path: str | None = None


def _sandbox_server(sb):
    """Build an in-process MCP server exposing this challenge's sandbox as a tool."""
    @tool("sandbox_bash", "Run a shell command inside the challenge sandbox",
          {"command": str})
    async def sandbox_bash(args):
        out = sb.bash(args["command"])
        return {"content": [{"type": "text", "text": out}]}

    return create_sdk_mcp_server(name="ctf", version="0.1", tools=[sandbox_bash])


def _block_text(block) -> str | None:
    """Pull text out of an assistant TextBlock or a ToolResultBlock (flags often
    land only in raw command output)."""
    if isinstance(block, TextBlock):
        return block.text
    if isinstance(block, ToolResultBlock):
        c = block.content
        if isinstance(c, str):
            return c
        if isinstance(c, list):
            return "\n".join(p.get("text", "") for p in c if isinstance(p, dict))
    return None


async def solve(ch: Challenge, max_turns: int = 40) -> Result:
    with make_sandbox(ch.workdir) as sb:
        # Recon first: deterministic probes sharpen routing and brief the specialist.
        # Its commands land in sb.actions, so they show up in the audit trail.
        brief = recon(sb, ch.prompt)
        spec = route(ch.category or brief["suggested"])
        options = ClaudeAgentOptions(
            system_prompt=SPECIALISTS[spec],
            mcp_servers={"ctf": _sandbox_server(sb)},
            allowed_tools=["mcp__ctf__sandbox_bash"],
            max_turns=max_turns,
        )
        task = (f"Challenge: {ch.name}\n\n{ch.prompt}\n\n{brief_text(brief)}\n\n"
                "The challenge files are in your current working directory. Find the flag.")

        found, turns, cost, thoughts = None, 0, None, []
        async for msg in query(prompt=task, options=options):
            if isinstance(msg, AssistantMessage):
                turns += 1  # counts even when we auto-terminate before ResultMessage
            if isinstance(msg, ResultMessage):
                turns, cost = msg.num_turns, msg.total_cost_usd
            for block in getattr(msg, "content", []) or []:
                text = _block_text(block)
                if not text:
                    continue
                # Keep assistant reasoning for the writeup; tool output is already
                # in sb.actions, so only reasoning blocks are added here.
                if isinstance(block, TextBlock):
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
    return Result(ch.name, spec, solved, found, turns, cost,
                  str(writeup_path), str(audit_path))
