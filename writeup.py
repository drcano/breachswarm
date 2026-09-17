"""Turn a solve's audit trace into a human CTF writeup — one LLM call, no tools.

The trace (list of {kind, ...} events) is the deterministic ground truth. The
writeup is just narration of it, so it can't invent steps that didn't happen.
"""
from __future__ import annotations

import json
from claude_agent_sdk import query, ClaudeAgentOptions

_SYS = (
    "You write CTF challenge writeups. Given the challenge and a chronological "
    "trace of what an automated solver actually did (shell commands, their output, "
    "and the solver's reasoning), produce a clear markdown writeup a human would "
    "publish: ## Challenge, ## Approach, ## Steps (what was tried, what worked, "
    "what failed and why), ## Flag, ## Takeaways. Be honest about dead ends — they "
    "make a writeup useful. Ground every claim in the trace; invent nothing."
)


def _render(trace: list[dict]) -> str:
    lines = []
    for e in trace:
        if e["kind"] == "cmd":
            lines.append(f"$ {e['command']}\n{e['output']}")
        elif e["kind"] == "thought":
            lines.append(f"[reasoning] {e['text']}")
        elif e["kind"] == "flag":
            lines.append(f"[FLAG FOUND] {e['text']}")
    return "\n\n".join(lines)[:100000]  # ponytail: cap; truncate oldest if a solve is huge


async def generate(name: str, prompt: str, trace: list[dict],
                   solved: bool, flag: str | None) -> str:
    task = (
        f"# Challenge: {name}\nStatus: {'SOLVED' if solved else 'unsolved'}"
        f"{' — ' + flag if flag else ''}\n\nDescription:\n{prompt}\n\n"
        f"Solver trace (chronological):\n\n{_render(trace)}"
    )
    md = []
    try:
        async for msg in query(prompt=task,
                               options=ClaudeAgentOptions(system_prompt=_SYS, max_turns=3)):
            for block in getattr(msg, "content", []) or []:
                if text := getattr(block, "text", None):
                    md.append(text)
    except Exception as e:  # writeup is a nicety — never let it fail a solve
        return _fallback(name, prompt, trace, solved, flag, e)
    return "\n".join(md) or _fallback(name, prompt, trace, solved, flag, None)


def _fallback(name, prompt, trace, solved, flag, err) -> str:
    """Deterministic writeup straight from the trace when the LLM call fails."""
    lines = [f"# {name}", f"Status: {'SOLVED' if solved else 'unsolved'}"
             + (f" — {flag}" if flag else ""), "", f"## Description\n{prompt}", "",
             "## Trace", "```", _render(trace), "```"]
    if err:
        lines += ["", f"_(LLM writeup unavailable: {err})_"]
    return "\n".join(lines)


def save_audit(path, trace: list[dict]) -> None:
    """Write the raw, deterministic audit log (one JSON event per line)."""
    with open(path, "w") as f:
        for e in trace:
            f.write(json.dumps(e) + "\n")
