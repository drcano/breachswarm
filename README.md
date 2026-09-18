# ctf-agent

An autonomous, multi-agent system that solves Capture-The-Flag challenges — and a
foundation for real offensive-security work (bug bounty, security research). Built
on the Claude Agent SDK.

**An orchestrator routes each challenge to a category specialist, which drives real
security tools inside an isolated sandbox until a flag appears — then writes up how
it did it.** Includes a full-stack web console for launching runs and watching them
live.

```
challenge ─▶ recon (deterministic probes) ─▶ orchestrator ─▶ specialist ─┐
                                                    (crypto/rev/pwn/       │  drives tools in a
                                                     web/forensics/misc)   │  Docker/local sandbox
                                                                           ▼
   flag ◀── writeup + audit log ◀── verifier (flag-format match, auto-stop)
```

## Results — InterCode-CTF (picoCTF-based, ground-truth flags)

**70/100 (70%) on the full InterCode-CTF set, pass@1** — one attempt per task, no
retries, Docker sandbox. Reproducible: `CTF_SANDBOX=docker python run.py
challenges/intercode --retries 0 -o results/intercode100.jsonl`. Raw evidence:
[results/intercode100.jsonl](results/intercode100.jsonl).

| Category | Strict solve (pass@1) |
|---|---|
| Reversing | 20/27 (74%) |
| Forensics | 13/15 (87%) |
| Crypto | 13/19 (68%) |
| General Skills / misc | 22/33 (67%) |
| Pwn (binary exploitation — weakest) | 1/4 |
| Web (live picoCTF servers now offline) | 1/2 |
| **Total** | **70/100 (70%)** — +6 near-miss (cracked but mis-formatted) |

Median time-to-flag on solved tasks: **13.5s** (fastest 0.3s via a zero-turn recon
pass, at no model cost).

Strict = exact match to the gold flag (the same check picoCTF runs). Real solves
include small-N/large-e/triple RSA, X.509 cert parsing, Vigenère, Morse,
transposition, LSB steg, pcap analysis, and static reversing. Numbers are the
honest, uncontaminated results (see the leak fix below). The Web tasks target live
picoCTF servers that are now offline, so they're unsolvable in an offline sandbox —
a dataset limit, not a solver gap. For reference, published CTF agents score ~22% on
the harder NYU-CTF / Cybench sets.

## What makes it work

- **Deterministic recon, not a second LLM.** A cheap `ls`/`file`/`strings` pass
  plus category-aware probes (checksec, tshark protocol hierarchy, zsteg, exif,
  archive listing) briefs each specialist so it starts informed — and often
  surfaces the flag itself.
- **Zero-turn fast-path.** If recon already found the flag, the challenge is solved
  with **no LLM call at all**.
- **Six expert specialists.** Each carries a tactical decision-tree playbook and a
  scoped tool set — crypto, reversing, pwn, web, forensics, general.
- **Deterministic verifier.** The flag format is the checker; the loop auto-stops
  the instant a real flag appears. Placeholder/encoded look-alikes are rejected.
- **Isolated sandboxes.** One Kali container per challenge (Rosetta runs x86-64 on
  Apple Silicon), or a local backend for fast iteration.
- **Every run is auditable.** A timestamped `audit.jsonl` (ground truth) plus an
  LLM-written `writeup.md` — the model can't claim a step it didn't take.

## Engineering rigor (the honest part)

- **Caught a benchmark leak.** An early run scored a suspicious 11/11 — the gold
  flag lived in a metadata file inside the sandbox and recon was reading it.
  Restructured so the agent sees only task files; all numbers are post-fix.
- **Measured iteration.** Crypto improved 9/19 → 13/19 after fixing an
  auto-terminator that stopped on rot13 flag look-alikes. Rev 6/10 → 8/10 after
  tightening flag extraction. Each fix: find the failure mode, fix, re-measure.
- **Crash-safe, parallel runner** with per-challenge retry and cost caps.

## Full-stack console

`server.py` (FastAPI) + `static/index.html` — a Matrix-themed dashboard to launch
runs, watch challenges flip SOLVED/near/fail live over SSE, and drill into any
challenge's audit trail and writeup. It's a thin layer over the same engine, so it
operates on real artifacts, not mocks.

```bash
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
./.venv/bin/uvicorn server:app --port 8000      # open http://localhost:8000
```

## CLI

```bash
# import the benchmark (gold flags kept OUT of the sandbox)
python import_intercode.py path/to/intercode/data/ctf -o challenges/intercode

# build the sandbox image
docker build -t ctf-agent:latest -f Dockerfile.lean .   # crypto/forensics/rev
docker build -t ctf-agent:full   -f Dockerfile.agent .  # + pwn/web/decompile tools

# run — parallel, cost-capped, with retries
./.venv/bin/python run.py challenges/intercode --per-category 8 \
    --concurrency 5 --max-turns 15 --retries 1
```

## Layout

| File | Role |
|---|---|
| `solver.py` | orchestrator + specialist runner + verifier + fast-path + retry |
| `recon.py` | deterministic recon + category-aware deep probes |
| `specialists.py` | six expert playbooks + category routing |
| `flag.py` | flag detection, scoring, near-miss, placeholder rejection |
| `sandbox.py` | Docker + local execution backends |
| `writeup.py` | audit-trace → human writeup |
| `run.py` | parallel batch runner + live solve-rate |
| `server.py` + `static/` | full-stack web console |
| `targets/` + `demo_live.sh` | live vulnerable apps for the real-world demos |
| `test_ctf_agent.py` | dependency-free unit tests for the logic core |
| `Dockerfile.lean` / `Dockerfile.agent` | sandbox images |

```bash
./.venv/bin/python test_ctf_agent.py     # 6 test groups, no deps
```

## Real-world validation — it exploits a live target

Beyond static CTF files, the web specialist was pointed at **live**
deliberately-vulnerable services (no local files — the bug-bounty setup) and
exploited two distinct vulnerability classes autonomously:

- **SSTI → RCE** (11 turns): recon'd the app, found a hidden endpoint, confirmed
  Jinja2 SSTI (`{{7*7}}`→`49`), escalated to remote code execution
  (`{{ cycler.__init__.__globals__.os.popen(...) }}`), and read the flag.
  → [docs/ssti_demo_writeup.md](docs/ssti_demo_writeup.md)
- **SQL injection** (24 turns): column-counted a UNION, orchestrated `sqlmap`,
  then — recognising a **boolean-blind** oracle — hand-wrote a binary-search
  extraction script to dump `SELECT flag FROM secret`.
  → [docs/sqli_demo_writeup.md](docs/sqli_demo_writeup.md)

Each run ends with a clean, publishable writeup the agent generated itself.

```bash
./demo_live.sh          # stands up both targets, unleashes the agent, tears down
```

The same loop applies to authorised bug-bounty targets and security research:
scoped hosts, an HTTP + browser toolkit, per-category network isolation, and a full
auditable trail.

### OWASP coverage

Run against purpose-built vulnerable targets (`targets/`, reproduce with
`./owasp_bench.sh`):

- **OWASP Web Top 10 — 7/7 demonstrable categories exploited** autonomously: IDOR,
  crypto/integrity failure, SQL & command injection, misconfiguration, JWT
  `alg:none` auth bypass, and SSRF.
- **OWASP LLM Top 10** — **Direct prompt injection (LLM01) genuinely exploited**:
  against an FS-isolated target (couldn't read its own source), a persistent
  injection extracted the system-prompt secret over HTTP in 39 turns. Excessive
  Agency (LLM06) — the tool-abuse *technique* is demonstrated, but a clean isolated
  re-run hits an infra limit (SDK-driven target + SDK-driven attacker → nested
  session errors), documented as a caveat, not claimed as a win. Indirect
  injection is topology-limited. **~1.5 of 10 categories are genuinely
  demonstrated** — scoped honestly rather than claimed wholesale.

Full matrix + the honest read: [docs/owasp_coverage.md](docs/owasp_coverage.md).
A dedicated **`llm` specialist** carries the OWASP LLM Top 10 playbook. Next:
GhidraMCP for decompilation and a multi-finding report generator.

## Read next

- **[CASE_STUDY.md](CASE_STUDY.md)** — unknown target → client-ready report, with
  measured unit economics (~$0.60–0.66/finding).
- **[DEMO.md](DEMO.md)** — 90-second demo storyboard + one-command reproductions.
- **[docs/GO_LIVE.md](docs/GO_LIVE.md)** — authorization checklist for a real
  bug-bounty engagement (the system refuses unauthorized targets).
- **[docs/owasp_coverage.md](docs/owasp_coverage.md)** — full OWASP Web + LLM
  matrix, honestly scoped.
- **[results/](results/)** — raw benchmark evidence (JSONL, ground-truth flags).
- [REPORT.md](REPORT.md) · [STATUS.md](STATUS.md) · `docs/how-it-works.html`
  (visual walkthrough).
