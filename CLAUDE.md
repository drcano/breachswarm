# ctf-agent — project context for Claude Code

Autonomous multi-agent offensive-security system on the Claude Agent SDK. Solves
CTFs and runs authorized bug-bounty assessments. Portfolio piece for an FDE role.

## Layout
- `solver.py` — orchestrator + specialist runner + deterministic verifier (core loop)
- `specialists.py` — category specialists (crypto/rev/pwn/web/forensics/misc/osint) + `llm`
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

## Current status (2026-09-22)
CTF side: InterCode-CTF **70/100 pass@1**. Executable CTF primitives (blind_extract / time_blind /
jwt_forge / ssrf_recon / symbolic_solve) + scratchpad + staged recon + archetype profiler + memory.

BOUNTY PIPELINE (the current focus — `bounty.py hunt()`): a research-grounded rebuild (see
`docs/hunter_playbook.md`). **24 agent tools** spanning the major web classes: discovery
(subdomain_recon/crawl[katana]/endpoint_recon/secret_scan[trufflehog]/dast_scan[nuclei -dast]),
access-control (authz_matrix + id-transform), SSRF (ssrf_recon/oob), auth (jwt_forge), blind
(blind_extract/time_blind), XSS incl. authenticated (browser_verify/browser_session[Playwright +
XHR capture]), and advanced classes (race [HTTP/2 single-packet, threads fallback] / mass_assign /
graphql / xxe / smuggle / protopollute / deserialize). All scope/rate-bound; loop-guardrails
(repeat_guard + --wall-cap). Image rebuilt WITH `h2` (single-packet race verified live in-sandbox).
- **`bench_bounty.py`** = the metric (bounty.hunt vs known-vuln targets, ground-truth flag scoring).
  Measured 2026-09-22: **4/4** on realistic targets (harbor BOLA / gauntlet 5-stage->RCE / chain
  SSRF->metadata / spa JS-XHR IDOR), ~$1-1.4 and <=1min each. Ceiling: **boss** (Fortress 4-stage,
  hard stage-1 WAF) **NOT solved** in 107 turns / $10.5 — the honest hard-target limit.
- **`bench_validator.py`** = validator precision/recall on the tuned corpus (1.0/1.0). Caught
  + fixed 3 real false-negatives (mixed-section BOLA; XSS-execution class; auth-session takeover w/
  Expected:403-vs-Actual:302 — from the PortSwigger campaign).
- **`bench_adversarial.py`** = HELD-OUT FP set (kills the teach-to-test caveat on the 1.0/1.0). Held-out
  data dropped precision to ~0.5 (8/12 FP); fixed via a theorized-impact gate + off-vocab impact terms
  → **3/12 FP, 0/4 FN** (~0.75). The 3 residual FPs are the honest ceiling — fabricated success /
  caller-owns-data / secret-name-not-value — semantic, need a truth-checker not a regex. See
  `docs/portswigger_results.md`.
- New bench targets for the advanced primitives: race_app / massassign_app / xxe_app / graphql_app.
Image rebuilt with the full arsenal (katana/trufflehog/nuclei-dast/playwright-chromium verified live).

EXTERNAL VALIDITY — PortSwigger EXPERT campaign (2026-09-22, `docs/portswigger_expert_campaign.md`):
12 Expert labs run, **10 solved / 1 partial / 1 fail** (~$50). The campaign was a bug-finder for the
pipeline itself — **5 fixes shipped, each with a test**:
1. `safety.py` blocks GET/POST action-endpoint deletes (`/admin/delete?username=`) — the pipeline was
   ACTUALLY deleting carlos on 2 labs (the old "correctly refuses delete" claim was FALSE until this).
2. `bounty.py` unique run dir (uuid) — parallel runs were clobbering each other's reports.
3. `safety.py`+doctrine block destructive METHOD calls in code-exec payloads (SSTI `gdprDelete()`);
   doctrine: on RCE, prove by READ/eval, never delete.
4. `validate.py` recognizes authenticated-session takeover — fixed a real account-takeover being
   silently rejected (false-negative); + bench regression positive.
5. `race` HTTP/2 single-packet primitive (Kettle); held-out adversarial validator FP set.
HONEST LIMITS: measured on external PortSwigger scope now (not just our targets). The pipeline
HAND-ROLLS even when a primitive exists (race, jwt) → roadmap #2/#3. Client-side Expert tier (XSS-
escape/DOM-clobber/cache→DOM) needs deliver-to-victim for the LAB banner, but for REAL bounty
`browser_verify` execution-proof is the correct deliverable (not a true capability gap).
ROADMAP (see campaign doc): #1 victim/exploit-server harness (lab-score, deprioritized) · #2 `race`
multi-request single-packet · #3 `jwt_forge` alg-confusion mode · #4 `protopollute` detect→exfil ·
#5 OOB collaborator tunnel (OOB_PUBLIC_URL). Autonomous business-logic bugs remain out of scope.
