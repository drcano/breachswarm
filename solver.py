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

import os
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


# --- Structural dead-end detector -------------------------------------------
# Prompt nudges didn't cut wasted turns (see docs/bounty_patterns.md); a directive
# to "chase the chain" made the agent FIXATE. This reacts to outcomes instead: it
# counts consecutive failure-dominated tool results and, past a threshold, appends
# an in-band "step back and widen" note — deterministic, no change to the query loop.
_FAIL_MARKERS = ("401", "403", "404", "refused", "timed out", "timeout",
                 "could not", "not found", "no such", "fetch error", "denied",
                 "invalid", "connection reset")


def _is_unproductive(out: str) -> bool:
    """True when a tool result carries no new signal — empty, or dominated by error
    markers with no success indicator. A flag is always productive."""
    low = out.lower()
    if "flag{" in low or "picoctf{" in low:
        return False
    if not out.strip():
        return True
    fails = sum(low.count(m) for m in _FAIL_MARKERS)
    has_ok = ("200 " in low or " 200\n" in low or '"data"' in low
              or "http/1.1 200" in low or "http/2 200" in low)
    return fails >= 2 and not has_ok


_STALL_WINDOW = 6      # look back this many tool results
_STALL_TRIGGER = 4     # this many dead-ends within the window fires the note
_STALL_COOLDOWN = 3    # stay quiet this many turns after firing (don't nag)


def _stall_nudge(out: str, state: dict) -> str:
    """Fire a widen-note when dead-ends are DENSE in a sliding window — not just
    strictly consecutive. Agents intersperse one good probe to dodge a consecutive
    counter (observed: streak capped at 3), but the fixation is still ~4-of-6 dead
    ends. state carries {'window':[bool], 'cooldown':int}. Disable with
    CTF_DETECTOR=0 (used by bench_detector.py to A/B-measure its effect)."""
    if os.getenv("CTF_DETECTOR", "1") == "0":
        return ""
    w = state.setdefault("window", [])
    w.append(_is_unproductive(out))
    if len(w) > _STALL_WINDOW:
        w.pop(0)
    if state.get("cooldown", 0) > 0:
        state["cooldown"] -= 1
        return ""
    if len(w) >= _STALL_TRIGGER + 1 and sum(w) >= _STALL_TRIGGER:
        state["cooldown"] = _STALL_COOLDOWN
        return ("\n\n[dead-end detector] " + str(sum(w)) + " of the last " + str(len(w))
                + " commands returned only errors/empties — you are likely stuck on "
                "one dimension. STOP repeating this class of probe. Widen: try a "
                "different endpoint/parameter/technique, or RE-USE something you "
                "already found (a leaked token/credential usually unlocks an endpoint "
                "you have ALREADY seen — including the same host via loopback "
                "127.0.0.1).")
    return ""


def _sandbox_server(sb):
    """Build an in-process MCP server exposing this challenge's sandbox as a tool.
    Wraps each result with the structural dead-end detector."""
    stall = {"window": [], "cooldown": 0}

    @tool("sandbox_bash", "Run a shell command inside the challenge sandbox",
          {"command": str})
    async def sandbox_bash(args):
        out = sb.bash(args["command"])
        return {"content": [{"type": "text", "text": out + _stall_nudge(out, stall)}]}

    return create_sdk_mcp_server(name="ctf", version="0.1", tools=[sandbox_bash])


def _decompiler_server(sb):
    """MCP server exposing a `decompile` tool for rev/pwn specialists.

    Backed by radare2 (already in the image); the *integration* is identical to
    wiring in an external GhidraMCP — swap the r2 command for a Ghidra
    analyzeHeadless call and nothing else changes. See docs/mcp_integration.md.
    """
    @tool("decompile",
          "Analyze a binary function and return Ghidra-quality pseudo-C when "
          "r2ghidra (pdg) is installed, otherwise annotated disassembly (pdf). "
          "One call beats fumbling raw r2 over bash.",
          {"binary": str, "function": str})
    async def decompile(args):
        b = args["binary"].replace("'", "")          # path in the sandbox
        fn = (args.get("function") or "main").replace("'", "")
        # analyze, seek to the function (by name or sym.<name>), pseudo-C + disasm
        # Prefer pdg (r2ghidra = Ghidra's decompiler engine) when installed,
        # fall back to pdc (r2's lighter built-in pseudo-C).
        cmd = (f"r2 -q -A -e scr.color=0 "
               f"-c 's {fn} 2>/dev/null || s sym.{fn} 2>/dev/null; "
               f"echo === PSEUDO-C ===; pdg 2>/dev/null || pdc 2>/dev/null; "
               f"echo === DISASM ===; pdf' '{b}' 2>&1 | head -300")
        return {"content": [{"type": "text", "text": sb.bash(cmd)}]}

    return create_sdk_mcp_server(name="decomp", version="0.1", tools=[decompile])


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
            servers = {"ctf": _sandbox_server(sb)}
            tools = ["mcp__ctf__sandbox_bash"]
            if spec in ("rev", "pwn"):  # binary work gets a decompiler MCP server
                servers["decomp"] = _decompiler_server(sb)
                tools.append("mcp__decomp__decompile")
            options = ClaudeAgentOptions(
                system_prompt=SPECIALISTS[spec],
                mcp_servers=servers,
                allowed_tools=tools,
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
