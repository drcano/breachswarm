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
| Pwn (binary exploitation)* | 1/4 |
| Web (live picoCTF servers now offline) | 1/2 |
| **Total** | **70/100 strict · 76/100 case-insensitive** |

The 6 gap tasks recover the **exactly correct** flag content and differ only in
letter case (e.g. `picoCTF{9c174346}` vs gold `picoCTF{9C174346}` — a hex hash;
or a decoded phrase the cipher emits uppercase). That's a known casing
inconsistency in the InterCode gold set, not a solver failure — hence both numbers
are reported. Median time-to-flag on solved tasks: **13.5s** (fastest 0.4s via a
zero-turn recon pass, at no model cost).

Strict = exact match to the gold flag (the same check picoCTF runs). Real solves
include small-N/large-e/triple RSA, X.509 cert parsing, Vigenère, Morse,
transposition, LSB steg, pcap analysis, and static reversing. Numbers are the
honest, uncontaminated results (see the leak fix below). **18 of the 100 tasks
reference a picoCTF remote server (netcat) that is now offline** — where the flag
is derivable from the provided files the agent still solves them by local
reproduction, but tasks whose flag lives only on the dead server are structurally
unsolvable in an offline sandbox (a dataset limit, not a solver gap). The 70/100
headline is left uncorrected for these rather than inflated by excluding them. For
reference, published CTF agents score ~22% on the harder NYU-CTF / Cybench sets.

## What makes it work

- **Deterministic recon, not a second LLM.** A cheap `ls`/`file`/`strings` pass
  plus category-aware probes (checksec, tshark protocol hierarchy, zsteg, exif,
  archive listing) briefs each specialist so it starts informed — and often
  surfaces the flag itself.
- **Zero-turn fast-path.** If recon already found the flag, the challenge is solved
  with **no LLM call at all**.
- **Expert specialists.** Each carries a tactical decision-tree playbook and a
  scoped tool set — crypto, reversing, pwn, web, forensics, general, osint, and an
  `llm` specialist for the OWASP LLM Top 10.
- **Deterministic verifier.** The flag format is the checker; the loop auto-stops
  the instant a real flag appears. Placeholder/encoded look-alikes are rejected.
- **Isolated sandboxes.** One Kali container per challenge (Rosetta runs x86-64 on
  Apple Silicon), or a local backend for fast iteration.
- **Every run is auditable.** A timestamped `audit.jsonl` (ground truth) plus an
  LLM-written `writeup.md` — the model can't claim a step it didn't take.
- **Retrieval knowledge base (RAG), measured.** 35 dense technique cards (37 chunks)
  across every specialist — web money-bugs, injection/SSRF/SSTI/deserialization/GraphQL/
  NoSQLi, crypto (RSA/padding-oracle), pwn (ROP/format-string), reversing, forensics —
  plus an exploit-**chains** playbook. The agent pulls cards on demand
  (`search_knowledge`), and recon **fingerprints the target and auto-loads the matching
  cards** into the brief (Werkzeug→SSTI, `/graphql`→GraphQL, PHP→LFI). Retrieval is stdlib
  TF-IDF; `eval_rag.py` gates it at **recall@1 26/28, recall@3 28/28** (up from 8/25 before
  the expansion). Grow it by dropping a `knowledge/*.md`. Coverage:
  [docs/knowledge_coverage.md](docs/knowledge_coverage.md).

## Engineering rigor (the honest part)

- **Caught a benchmark leak.** An early run scored a suspicious 11/11 — the gold
  flag lived in a metadata file inside the sandbox and recon was reading it.
  Restructured so the agent sees only task files; all numbers are post-fix.
- **Measured iteration.** Crypto improved 9/19 → 13/19 after fixing an
  auto-terminator that stopped on rot13 flag look-alikes. Rev 6/10 → 8/10 after
  tightening flag extraction. Each fix: find the failure mode, fix, re-measure.
- **Crash-safe, parallel runner** with per-challenge retry and cost caps.

## Measured architecture decisions — what won, what lost

The interesting engineering isn't the code that shipped, it's the code that was *measured
and rejected*. A head-to-head A/B harness (`bench_orchestrator.py`) pit a single-agent
baseline against a **multi-agent exploit orchestrator** (a lead agent that plans a kill
chain and delegates each stage to fresh specialist sub-agents on a shared blackboard) and a
**stateful** single agent (explicit artifact blackboard) on two chained targets — Fortress
(4-stage) and Gauntlet (5-stage).

| target | mode | solved | avg wall | verdict |
|---|---|---|---|---|
| Gauntlet (5-stage) | baseline | **2/2** | 187s | fastest |
| | stateful | **2/2** | 164s | ties baseline |
| | orchestrator | **1/2** | 280s solve / 993s fail | never wins, always costs real $ |
| Fortress (4-stage) | baseline | 0/2* | 1167s | *validation run solved (~1030s) |
| | orchestrator | 0/1 | 2817s | most expensive ($6.51/run) |

**The multi-agent orchestrator did not win** — it never beat baseline on solve rate and
always cost real time/$ (its one Gauntlet solve was ~1.5× a baseline solve at $1.70; its
failures ran 993s–2817s), where a single agent early-exits for ~nothing and already carries
chain state fine. Explicit state merely tied. (N=2 — the cost/latency gap is robust, the
solve-rate delta suggestive.) **A single well-equipped agent (RAG + recon-playbook) stays the default;** the
orchestrator and stateful modes are kept as opt-in, documented experiments. The A/B harness
also acted as a fuzzer, surfacing **three real correctness bugs** in the solve loop
(silent-decoy flail, crash-on-budget-exhaustion, false-positive flag match) — fixed, with
regression tests for the two logic bugs. And a clean finding: **chain depth ≠ difficulty** — the deeper
Gauntlet solved in ~3 min while Fortress's WAF-evasion S1 was the real wall. A follow-up
**RAG ablation** (full vs KB-only vs no-RAG on Gauntlet) then found **no measurable RAG lift
there** — all 2/2, wall/turns within noise — because the base model already knows those
techniques; RAG's value, if any, is on rarer/precise payloads (untested). Honest and a little
humbling. Full writeups + numbers:
[docs/OVERNIGHT.md](docs/OVERNIGHT.md).

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
| `recon.py` | deterministic recon + web enumeration + recon→playbook auto-load |
| `specialists.py` | expert playbooks (crypto/rev/pwn/web/forensics/misc/osint/llm) + routing |
| `knowledge_base.py` + `knowledge/` | RAG: TF-IDF retriever + 35 technique cards |
| `eval_rag.py` | retrieval eval harness (recall@1/@3), corpus-growth guardrail |
| `orchestrator.py` · `stateful.py` | opt-in multi-agent & stateful chain solvers (A/B) |
| `bench_orchestrator.py` · `analyze_ab.py` | chain A/B harness + summarizer |
| `flag.py` | flag detection, scoring, near-miss, placeholder + decoy rejection |
| `sandbox.py` | Docker + local execution backends |
| `writeup.py` | audit-trace → human writeup |
| `run.py` | parallel batch runner + live solve-rate |
| `server.py` + `static/` | full-stack web console |
| `targets/` + `demo_live.sh` | live vulnerable apps for the real-world demos |
| `test_ctf_agent.py` | dependency-free unit tests for the logic core |
| `Dockerfile.lean` / `Dockerfile.agent` | sandbox images |

```bash
./.venv/bin/python test_ctf_agent.py     # 10 test groups, no deps
./.venv/bin/python eval_rag.py           # RAG retrieval eval (recall@1/@3)
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

### Third-party targets — full findings reports

Pointed at real, third-party OWASP-style vulnerable apps it had never seen, the
bounty pipeline (`bounty.py`, scope-gated) produced client-ready reports:

- **OWASP Juice Shop** — 8 findings incl. 2 Critical SQLi (auth bypass + full
  credential dump). → [docs/juiceshop_findings.md](docs/juiceshop_findings.md)
- **VAmPI (vulnerable API)** — 6 findings, 4 Critical, in 27 turns / 138s / $1.01:
  unauth UNION SQLi credential dump, forged JWT (weak secret `random`), BOLA admin
  password reset, mass-assignment admin, `/_debug` cleartext-password leak.
  → [docs/vampi_findings.md](docs/vampi_findings.md)
- **testasp.vulnweb.com (LIVE external target)** — first run against a real host on
  the internet (Acunetix's authorized-for-scanning test site), through the
  **`--enforce`** no-bypass egress guard at 2 req/s: 5 findings incl. 2 Critical SQLi
  (auth bypass + DB read) and path traversal, in 26 turns / 101s / $0.99. One finding
  independently re-verified by hand. → [docs/vulnweb_findings.md](docs/vulnweb_findings.md)
- **rest.vulnweb.com (LIVE external REST API)** — Invicti's authorized Vulnerable
  REST API, enforced egress: 6 findings incl. UNION SQLi (dumped users, SHA-1 hashes,
  OAuth secret `n3tsp4rk3r_s3cr3t`, MySQL `root@%`), forgeable JWT (`supersecret`),
  and XXE file read — 69 turns / 339s / $1.85. UNION SQLi independently re-verified.
  → [docs/vulnweb_rest_findings.md](docs/vulnweb_rest_findings.md)

Each finding carries a CVSS 3.1 vector, CWE, affected asset, repro steps, impact,
and remediation. See [CASE_STUDY.md](CASE_STUDY.md) for the measured economics (SDK-reported cost).

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

- **[docs/OVERNIGHT.md](docs/OVERNIGHT.md)** — the RAG expansion, the multi-agent A/B
  (measured & rejected), the three bugs the harness caught, and the ranked next steps.
- **[docs/knowledge_coverage.md](docs/knowledge_coverage.md)** — the full RAG corpus index.
- **[docs/rag_ablation.md](docs/rag_ablation.md)** — does the RAG actually help solving? (measured: no lift on standard-technique chains).
- **[docs/targets.md](docs/targets.md)** — vetted authorized proving-ground & bounty targets.
- **[CASE_STUDY.md](CASE_STUDY.md)** — unknown target → client-ready report, with
  measured unit economics (~$0.60–0.66/finding).
- **[DEMO.md](DEMO.md)** — 90-second demo storyboard + one-command reproductions.
- **[docs/GO_LIVE.md](docs/GO_LIVE.md)** — authorization checklist for a real
  bug-bounty engagement (the system refuses unauthorized targets).
- **[docs/owasp_coverage.md](docs/owasp_coverage.md)** — full OWASP Web + LLM
  matrix, honestly scoped.
- **[docs/mcp_integration.md](docs/mcp_integration.md)** — how MCP servers are
  wired into the agent loop (in-process vs external; the decompiler tool).
- **[results/](results/)** — raw benchmark evidence (JSONL, ground-truth flags).
- [REPORT.md](REPORT.md) · [STATUS.md](STATUS.md) — *early build logs (partial numbers, superseded by the 70/100 above)* · `docs/how-it-works.html`
  (visual walkthrough).
