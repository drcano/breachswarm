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

from flag import find_flag, is_correct, is_near_miss
from recon import recon, brief_text
from sandbox import make_sandbox
from specialists import SPECIALISTS, route
from writeup import generate, save_audit


@dataclass
class Challenge:
    name: str
    category: str | None
    prompt: str            # the challenge description shown to solvers
    workdir: str           # dir with ONLY the task files, exposed to the agent
    outdir: str = ""       # where to write audit/writeup (outside the sandbox); defaults to workdir
    flag_pattern: str | None = None
    real_flag: str | None = None   # set by the benchmark for scoring; None in live CTF


@dataclass
class Result:
    name: str
    specialist: str
    solved: bool
    near_miss: bool
    flag: str | None
    turns: int
    cost_usd: float | None = None
    duration_s: float | None = None       # wall-clock for the whole solve
    time_to_flag_s: float | None = None    # from start to the flag appearing
    writeup_path: str | None = None
    audit_path: str | None = None
    error: str | None = None   # set when the run errored (e.g. rate limit); excluded from scoring


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


async def solve(ch: Challenge, max_turns: int = 40, retries: int = 0) -> Result:
    # Network only for categories that need a live (authorised) target; untrusted
    # binaries (pwn/rev/forensics) run air-gapped so they can't call home.
    t0 = time.time()
    needs_net = route(ch.category) in ("web", "osint", "llm")
    with make_sandbox(ch.workdir, network=needs_net) as sb:
        # Recon first: deterministic probes sharpen routing and brief the specialist.
        # Its commands land in sb.actions, so they show up in the audit trail.
        brief = recon(sb, ch.prompt)
        spec = route(ch.category or brief["suggested"])

        found, turns, cost, thoughts = None, 0, None, []

        # Fast path: recon (ls/file/strings) may have already surfaced the flag
        # (very common in forensics/general). Solve with zero LLM turns.
        for act in sb.actions:
            if hit := find_flag(act.get("output", ""), ch.flag_pattern):
                found = hit
                cost = 0.0  # zero-turn recon solve — genuinely free, not "unknown"
                break

        if not found:
            options = ClaudeAgentOptions(
                system_prompt=SPECIALISTS[spec],
                mcp_servers={"ctf": _sandbox_server(sb)},
                allowed_tools=["mcp__ctf__sandbox_bash"],
                max_turns=max_turns,
            )
            base = (f"Challenge: {ch.name}\n\n{ch.prompt}\n\n{brief_text(brief)}\n\n"
                    "The challenge files are in your current working directory. Find the flag.")
            # Up to (1 + retries) attempts; each retry nudges a different approach.
            for attempt in range(retries + 1):
                task = base if attempt == 0 else base + (
                    "\n\nYour previous attempt did NOT find the flag. Try a different "
                    "technique, tool, or encoding, and re-check your decoding step.")
                async for msg in query(prompt=task, options=options):
                    if isinstance(msg, AssistantMessage):
                        turns += 1  # accumulates across attempts
                    if isinstance(msg, ResultMessage) and msg.total_cost_usd is not None:
                        cost = (cost or 0) + msg.total_cost_usd  # accumulate; 0.0 is a real value
                    for block in getattr(msg, "content", []) or []:
                        text = _block_text(block)
                        if not text:
                            continue
                        # Tool output is already in sb.actions; keep only reasoning here.
                        if isinstance(block, TextBlock):
                            thoughts.append({"t": time.time(), "kind": "thought", "text": text})
                        if hit := find_flag(text, ch.flag_pattern):
                            found = hit
                    if found:
                        break  # auto-terminate once the flag appears
                if found:
                    break

        # Merge command log + reasoning into one chronological trace.
        trace = sorted(sb.actions + thoughts, key=lambda e: e["t"])
        ttf = round(time.time() - t0, 1) if found else None
        if found:
            trace.append({"t": time.time(), "kind": "flag", "text": found})

    duration_s = round(time.time() - t0, 1)
    solved = is_correct(found, ch.real_flag)
    near = is_near_miss(found, ch.real_flag)
    out = Path(ch.outdir or ch.workdir)
    audit_path = out / "audit.jsonl"
    writeup_path = out / "writeup.md"
    save_audit(audit_path, trace)
    writeup_path.write_text(await generate(ch.name, ch.prompt, trace, solved, found))
    return Result(ch.name, spec, solved, near, found, turns, cost,
                  duration_s, ttf, str(writeup_path), str(audit_path))
