"""Parallel read-only recon subagents.

Splits an assessment into its parallelizable part (mapping the attack surface) and
its sequential part (exploitation/chaining, which must stay in ONE stateful agent).
Each subagent maps a single dimension READ-ONLY and returns candidate attack points;
the coordinator merges them into a surface map the exploitation agent starts from.

Motivation (measured): rest.vulnweb.com took 69 turns because a broad REST surface
was enumerated serially. Fanning recon out should give the exploitation agent a
fuller map up front. Whether that lowers TOTAL turns/cost (recon subagents cost
tokens too) is an empirical question — measure it, don't assume. All subagents share
one sandbox and therefore the one rate-limited egress path, so parallelism never
raises the request rate against the target.
"""
import asyncio
import time

from claude_agent_sdk import (query, ClaudeAgentOptions,
                              AssistantMessage, ResultMessage)

from solver import _sandbox_server, _block_text
from config import MODEL

_SYS = (
    "You are a focused RECON subagent in a sandboxed Kali container with a "
    "sandbox_bash tool. STRICTLY READ-ONLY: safe GETs and at most one probe per "
    "input — do NOT exploit, do NOT modify data, do NOT run heavy scanners "
    "(no sqlmap, no big ffuf/wordlists). Map ONLY your assigned dimension in a "
    "handful of commands, then output a terse bullet list of concrete candidate "
    "attack points as `- <endpoint/param> — <why worth exploiting>`. No prose, no "
    "exploitation."
)

# One focused dimension per subagent. Keep the set small — this is the
# parallelizable slice, not the whole job.
AREAS = {
    "surface": "Discover endpoints/routes/methods and their parameters (crawl links "
               "in responses, try common API paths like /api, /users, /login).",
    "auth": "Map the auth surface: login endpoints, tokens/JWT, session cookies, "
            "default-credential hints, roles/privilege levels.",
    "injection": "Identify likely-injectable inputs (id/search/filter/path params) "
                 "and capture any error signal from ONE safe single-quote probe each.",
}


# Recon shares the system MODEL (config.py). The diagnostic showed model quality
# drives map quality (haiku flailed, sonnet/opus prioritize) — worth the tokens.
RECON_MODEL = MODEL  # entire system on one model (see config.py)


async def _run_area(sb, target: str, ctx: str, name: str, focus: str,
                    max_turns: int, model: str = RECON_MODEL) -> dict:
    opts = ClaudeAgentOptions(
        system_prompt=_SYS, mcp_servers={"ctf": _sandbox_server(sb)},
        allowed_tools=["mcp__ctf__sandbox_bash"], max_turns=max_turns, model=model)
    prompt = (f"Target: {target}\n{ctx}\nRECON DIMENSION — {name}: {focus}")
    turns, cost, texts, usages = 0, 0.0, [], []
    try:
        async for msg in query(prompt=prompt, options=opts):
            if isinstance(msg, AssistantMessage):
                turns += 1
            if isinstance(msg, ResultMessage):
                if msg.total_cost_usd is not None:
                    cost += msg.total_cost_usd
                if msg.model_usage:
                    usages.append(msg.model_usage)
            for b in getattr(msg, "content", []) or []:
                t = _block_text(b)
                if t:
                    texts.append(t)
    except Exception as e:
        # recon is best-effort — hitting the turn cap (SDK raises) or any error
        # returns the partial map instead of crashing the whole assessment.
        texts.append(f"[recon:{name} stopped early: {str(e)[:80]}]")
    return {"area": name, "turns": turns, "cost": round(cost, 4),
            "usages": usages, "map": "\n".join(texts)[-1500:]}


async def parallel_recon(sb, target: str, ctx: str = "", areas=None,
                         max_turns: int = 8, model: str = RECON_MODEL) -> dict:
    """Fan out read-only recon subagents (sharing `sb`); return a merged surface map
    plus total turns/cost/wall-clock so the caller can measure the trade."""
    areas = areas or list(AREAS)
    t0 = time.time()
    res = await asyncio.gather(*[
        _run_area(sb, target, ctx, a, AREAS[a], max_turns, model) for a in areas])
    surface_map = "\n\n".join(f"### recon:{r['area']} ({r['turns']}t)\n{r['map']}"
                              for r in res)
    return {
        "map": surface_map,
        "turns": sum(r["turns"] for r in res),
        "cost": round(sum(r["cost"] for r in res), 4),
        "usages": [u for r in res for u in r["usages"]],
        "wall_s": round(time.time() - t0, 1),
        "areas": res,
    }
