"""Multi-agent exploit orchestrator (the "exploit agent on top").

A single specialist already solves most chains because one context remembers every
artifact. This is the SPECULATIVE alternative the FDE story wants to show and MEASURE:
a lead orchestrator that PLANS a kill chain and DELEGATES each stage to a fresh
specialist sub-agent, carrying discovered artifacts (tokens/keys/URLs/roles) forward
on a shared blackboard. Fresh sub-contexts resist the long-context fixation that a
single agent hits on deep chains — the hypothesis under test.

Whether it beats the single agent is an OPEN question — see bench_orchestrator.py and
docs/OVERNIGHT.md for the head-to-head. Kept only if it wins.

Mechanism (all on the Agent SDK): the orchestrator is a query() loop whose tools are
  - sandbox_bash      : recon / verify itself
  - search_knowledge  : the RAG playbook (esp. the chains card)
  - record_artifact   : write a discovered token/key/url/role to the blackboard
  - run_specialist    : spawn a NESTED query() loop (web specialist prompt, SAME
                        sandbox, current blackboard injected) for one stage objective
Everything shares one sandbox, so every sub-agent sees the same live target.
"""
from __future__ import annotations

import time
from pathlib import Path

from claude_agent_sdk import (query, ClaudeAgentOptions, tool, create_sdk_mcp_server,
                              AssistantMessage, TextBlock, ResultMessage)
from config import MODEL
from flag import find_flag, is_correct
from specialists import SPECIALISTS
from solver import _knowledge_server, _block_text, _decoy_nudge, _waf_nudge, _rate_nudge
from sandbox import make_sandbox
from recon import recon, brief_text

ORCH_SYS = (
    "You are the LEAD exploit engineer running an AUTHORIZED assessment. You win by "
    "chaining primitives into critical impact, not by finding one bug. You PLAN and "
    "DELEGATE rather than doing every keystroke yourself.\n\n"
    "Tools:\n"
    "- sandbox_bash: recon and quickly verify things yourself.\n"
    "- search_knowledge: the offensive playbook (RAG). Read the 'chains' card first.\n"
    "- record_artifact(key,value): save a discovered token / api key / credential / "
    "internal URL / role to the shared blackboard so later stages reuse it.\n"
    "- run_specialist(objective): hand ONE focused exploitation objective to a "
    "specialist operator who shares your sandbox and sees the blackboard; it returns "
    "its findings. Use it for the actual exploitation of each stage.\n\n"
    "Method: (1) recon the surface. (2) consult the chains playbook. (3) split the "
    "goal into ORDERED stages; delegate each as a single crisp objective to "
    "run_specialist, telling it exactly what is known and what to obtain. (4) when a "
    "stage yields an artifact, record_artifact it immediately. (5) feed artifacts into "
    "the next objective — a gate ('admin only', 'requires X') means X is your next "
    "objective, not a dead end. (6) STOP as soon as the flag / critical impact lands; "
    "print the flag on its own line. Keep the request footprint low."
)


def _orchestrator_servers(sb, blackboard, counters):
    """Build the orchestrator's MCP tools. run_specialist spawns a nested specialist
    query() over the SAME sandbox with the blackboard injected — the multi-agent core.
    counters accumulates turns/cost/usages across every sub-agent."""

    waf_state = {}

    @tool("sandbox_bash", "Run a shell command in the shared sandbox (recon/verify)",
          {"command": str})
    async def sandbox_bash(args):
        out = sb.bash(args.get("command", ""))
        return {"content": [{"type": "text", "text": out + _decoy_nudge(out)
                             + _waf_nudge(out, waf_state) + _rate_nudge(out, waf_state)}]}

    @tool("record_artifact",
          "Save a discovered artifact (token/key/credential/internal-url/role) to the "
          "shared blackboard so later stages reuse it.", {"key": str, "value": str})
    async def record_artifact(args):
        k, v = args.get("key", "").strip(), args.get("value", "").strip()
        if k:
            blackboard[k] = v
        return {"content": [{"type": "text", "text":
                f"recorded {k!r}. blackboard now: {blackboard}"}]}

    @tool("run_specialist",
          "Delegate ONE focused exploitation objective to a specialist operator that "
          "shares your sandbox and the blackboard. Returns its findings/artifacts.",
          {"objective": str})
    async def run_specialist(args):
        objective = args.get("objective", "")
        bb = "\n".join(f"  {k} = {v}" for k, v in blackboard.items()) or "  (empty)"
        task = (f"AUTHORIZED assessment. Focused objective for THIS stage:\n{objective}\n\n"
                f"Known artifacts on the shared blackboard (reuse these):\n{bb}\n\n"
                "Do ONLY this stage. Confirm with a minimal proof. At the end, state on "
                "their own lines any new artifact you recovered as `ARTIFACT <key>: "
                "<value>` (e.g. a token, key, url, role), and the flag if you get it.")
        srv = {"ctf": create_sdk_mcp_server(name="ctf", version="1.0", tools=[sandbox_bash]),
               "kb": _knowledge_server()}
        opts = ClaudeAgentOptions(
            system_prompt=SPECIALISTS["web"],
            mcp_servers=srv,
            allowed_tools=["mcp__ctf__sandbox_bash", "mcp__kb__search_knowledge"],
            max_turns=counters["spec_max_turns"], model=MODEL)
        out_text, flag = [], None
        fp = counters.get("flag_pattern")
        try:
            async for msg in query(prompt=task, options=opts):
                if isinstance(msg, AssistantMessage):
                    counters["turns"] += 1
                if isinstance(msg, ResultMessage):
                    if msg.total_cost_usd:
                        counters["cost"] += msg.total_cost_usd
                    if msg.model_usage:
                        counters["usages"].append(msg.model_usage)
                for b in getattr(msg, "content", []) or []:
                    t = _block_text(b)
                    if t and isinstance(b, TextBlock):
                        out_text.append(t)
                        if hit := find_flag(t, fp):
                            flag = hit
        except Exception as e:  # SDK raises on max_turns; salvage partial output
            out_text.append(f"[specialist stopped: {e}]")
        summary = "\n".join(out_text[-6:]) or "(no textual output)"
        if flag:
            counters["flag"] = counters.get("flag") or flag
        # auto-capture ARTIFACT lines the sub-agent declared, into the blackboard
        for line in "\n".join(out_text).splitlines():
            if line.strip().lower().startswith("artifact "):
                body = line.strip()[len("artifact "):]
                if ":" in body:
                    k, _, v = body.partition(":")
                    blackboard[k.strip()] = v.strip()
        return {"content": [{"type": "text", "text":
                f"[specialist returned]\n{summary}\n\nblackboard: {blackboard}"}]}

    srv = create_sdk_mcp_server(name="orch", version="1.0",
                                tools=[sandbox_bash, record_artifact, run_specialist])
    return {"orch": srv, "kb": _knowledge_server()}


async def solve_chain(name: str, prompt: str, workdir: str, real_flag: str | None = None,
                      outdir: str = "", orch_max_turns: int = 16,
                      spec_max_turns: int = 20,
                      flag_pattern: str = r"flag\{[^}\s]+\}") -> dict:
    """Run the orchestrator against a target. Returns a metrics dict comparable to the
    single-agent baseline (solver.solve): solved/turns/cost/duration/artifacts."""
    t0 = time.time()
    blackboard: dict[str, str] = {}
    counters = {"turns": 0, "cost": 0.0, "usages": [], "flag": None,
                "spec_max_turns": spec_max_turns, "flag_pattern": flag_pattern}
    with make_sandbox(workdir, network=True) as sb:
        brief = recon(sb, prompt)
        servers = _orchestrator_servers(sb, blackboard, counters)
        opts = ClaudeAgentOptions(
            system_prompt=ORCH_SYS, mcp_servers=servers,
            allowed_tools=["mcp__orch__sandbox_bash", "mcp__orch__record_artifact",
                           "mcp__orch__run_specialist", "mcp__kb__search_knowledge"],
            max_turns=orch_max_turns, model=MODEL)
        task = (f"Target: {name}\n\n{prompt}\n\n{brief_text(brief)}\n\n"
                "Plan the kill chain and delegate each stage. Find the flag.")
        found = None
        try:
            async for msg in query(prompt=task, options=opts):
                if isinstance(msg, AssistantMessage):
                    counters["turns"] += 1
                if isinstance(msg, ResultMessage):
                    if msg.total_cost_usd:
                        counters["cost"] += msg.total_cost_usd
                    if msg.model_usage:
                        counters["usages"].append(msg.model_usage)
                for b in getattr(msg, "content", []) or []:
                    t = _block_text(b)
                    if t and (hit := find_flag(t, flag_pattern)):
                        found = hit
        except Exception as e:
            print(f"[orchestrator stopped: {e}]")
        found = found or counters.get("flag")
    dur = round(time.time() - t0, 1)
    from pricing import summarize
    usage = summarize(counters["usages"])
    solved = is_correct(found, real_flag)
    row = {"mode": "orchestrator", "name": name, "solved": solved, "flag": found,
           "turns": counters["turns"], "cost_usd": round(counters["cost"], 4),
           "duration_s": dur, "tokens": usage["tokens"],
           "cost_sdk_usd": usage["cost_sdk_usd"], "artifacts": dict(blackboard),
           "orch_max_turns": orch_max_turns, "spec_max_turns": spec_max_turns}
    return row


if __name__ == "__main__":  # smoke: prompt/tool wiring builds without a live target
    bb, cnt = {}, {"turns": 0, "cost": 0.0, "usages": [], "flag": None,
                   "spec_max_turns": 5}

    class _SB:  # noqa
        def bash(self, c): return "ok"
    s = _orchestrator_servers(_SB(), bb, cnt)
    assert set(s) == {"orch", "kb"} and "LEAD exploit engineer" in ORCH_SYS
    print("orchestrator.py ok — tools:", list(s))
