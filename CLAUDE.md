# ctf-agent — project context for Claude Code

Autonomous multi-agent offensive-security system on the Claude Agent SDK. Solves
CTFs and runs authorized bug-bounty assessments. Portfolio piece for an FDE role.

## Layout
- `solver.py` — orchestrator + specialist runner + deterministic verifier (core loop)
- `specialists.py` — 6 category specialists (crypto/rev/pwn/web/forensics/misc) + `llm`
- `recon.py` — deterministic category-aware probes (no LLM); can zero-turn solve
- `run.py` — parallel batch runner over `challenges/<set>/*/challenge.json`
- `sandbox.py` — Docker/local sandbox factory (per-category network isolation)
- `bounty.py` — authorized bounty runner; `scope.py` guardrail; `egress_proxy.py`
  (no-bypass egress via `--enforce`); `report.py` (HackerOne/Bugcrowd findings)
- `server.py` + `static/` — FastAPI console (`/`) + metrics dashboard (`/dashboard`)
- `targets/` — deliberately-vulnerable demo apps (built into `vuln-target:latest`)
- `results/` — tracked benchmark evidence (JSONL); `docs/` — writeups, coverage, GO_LIVE

## Running things
- Tests: `./.venv/bin/python test_ctf_agent.py` (dependency-free) + `python scope.py`
- Benchmark (pass@1): `CTF_SANDBOX=docker python run.py challenges/intercode --retries 0 -o results/intercode100.jsonl`
- Bench scripts: `./owasp_bench.sh` `./modern_bench.sh` `./hard_bench.sh` `./demo_live.sh`
- Bounty run: `python bounty.py --scope <file> --target <url> [--enforce]`

## Conventions & hard rules
- Use `./.venv/bin/python` (project venv).
- Docker runtime is Colima on M1 (overlay2 driver, Rosetta for x86-64).
- **Concurrency ≤ 3** on full runs — a concurrency-4 burst hit the account session
  limit and truncated a run at task 43.
- **Never** point the agent at a real external host without: a program that permits
  automated testing + declared scope + explicit user go-ahead. `scope.py` hard-refuses
  `authorized != true`; always-deny: cloud metadata, `.gov`, `.mil`, localhost.
- Flags/gold answers must never enter the sandbox (challenge files live in `files/`).
- Be rigorously honest in results: report measured numbers and named limits, not
  inflated claims. See `docs/owasp_coverage.md` for the honest LLM scoping.

## Current status (2026-09-17)
InterCode-CTF **70/100 pass@1**. Three third-party validations: InterCode, Juice
Shop (8 findings), VAmPI (6 findings). Next: real authorized bounty run (staged,
see `docs/GO_LIVE.md`); record the 90s demo (`DEMO.md`).
