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

| Category | Strict solve |
|---|---|
| Crypto (full 19-task category) | 13/19 (68%) |
| General Skills | 8/8 |
| Forensics | 9/10 (90%) |
| Reversing | 8/10 (80%) |
| **Balanced 6-category run (38 tasks, full toolset + retries)** | **27/38 (71%)** — 75% excluding dead-server web tasks; 1164s @ concurrency 5 |

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
| `Dockerfile.lean` / `Dockerfile.agent` | sandbox images |

## Toward real-world use

The same loop that solves CTF web challenges applies to bug-bounty recon and
security research: scoped targets, a browser + HTTP toolkit, and an auditable trail
of everything the agent did. Next: GhidraMCP for decompilation, a Playwright-driven
web agent against deliberately-vulnerable targets, and a findings report generator.

See [REPORT.md](REPORT.md) for the full findings and [STATUS.md](STATUS.md) for the
build log. `docs/how-it-works.html` is a visual walkthrough.
