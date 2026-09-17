# ctf-agent

Multi-agent CTF solver on the Claude Agent SDK. Orchestrator routes a challenge
to a category specialist, which drives tools inside a per-challenge Docker
sandbox; a flag-shaped output auto-terminates the loop.

```
challenge.json ─▶ route() ─▶ specialist (system prompt + sandbox_bash tool)
                                   │  runs bash in Docker sandbox (/work)
                                   ▼
                          find_flag() on every output ─▶ stop + score
```

## Files
- `flag.py` — flag detection + scoring (the auto-terminate core). `python3 flag.py` self-checks.
- `sandbox.py` — one Docker container per challenge; `bash()` execs inside it.
- `specialists.py` — per-category system prompts + `route()`.
- `solver.py` — orchestrator + Agent SDK runner + verifier.
- `run.py` — batch a folder, write `results.jsonl`, print solve rate.
- `../Dockerfile.agent` — the sandbox image (Kali + ranked tools).

## Setup
```bash
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
# needs the `claude` CLI on PATH (the SDK drives it)
```

## Run
Two sandbox backends, chosen by `CTF_SANDBOX` (default `docker`):

```bash
# local backend — runs commands on the host in the challenge dir.
# NO isolation: trusted challenges only (crypto/forensics/misc), never pwn/rev.
CTF_SANDBOX=local ./.venv/bin/python run.py examples/

# docker backend — one isolated container per challenge (needs a docker runtime)
docker build -t ctf-agent:latest -f Dockerfile.agent .
./.venv/bin/python run.py challenges/
```

Each solve writes `audit.jsonl` (deterministic log of every command + reasoning)
and `writeup.md` (LLM narration of that log) into the challenge dir.

**Status:** end-to-end pipeline works on the local backend (solves the base64
smoke test in `examples/`). Docker backend is written but untested — no runtime
installed yet.

## Deliberately not built yet (add when the baseline shows you need it)
- **Rev/pwn/web MCP tools** (GhidraMCP, pwndbg-mcp, Playwright MCP) — wire into
  `solver.py`'s `mcp_servers` once crypto/forensics baseline works. Highest-
  leverage next step per the research (stateful tools > agent loop).
- **LLM verifier/critic** — current verifier is deterministic (regex + exact
  match). Add an LLM critic only if wrong-but-well-formed flags become a problem.
- **LLM category fallback** — `route()` trusts the benchmark's category label;
  add classification only for unlabeled/live challenges.
- **Parallelism** — `run.py` is sequential. Parallelize across challenges when
  runtime hurts.
- **Network wiring** for web/pwn targets — `sandbox.py` runs with no network by
  default; add the target container/network for those categories.

## Eval targets
NYU CTF Bench (200, ground-truth flags) and Cybench (40). SOTA ~22% — the bar.
```
