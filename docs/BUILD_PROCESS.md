# Build Process — an auditable record

How this system was built, in order, with the decision behind each step and the
measured result. Every claim maps to a commit (`git log --reverse`); results are
reproducible from the scripts named. Nothing here is aspirational — it's what
happened.

## Phase 0 — Framing (why this exists)

Goal: a portfolio project proving Forward-Deployed-Engineer capability — an
AI system used in a messy real environment, measured honestly. Chose an
autonomous **multi-agent CTF solver** (orchestrator + category specialists) on the
Claude Agent SDK, with a hard rule: **measure everything on a fixed benchmark
(InterCode-CTF) so every change gets a number.**

## Phase 1 — Skeleton, then a working loop

- `Initial skeleton` — orchestrator → specialist → verifier, per-challenge sandbox,
  flag-checker that auto-terminates. Wrote the pieces against the real SDK 0.2.154
  API (introspected, not guessed).
- `Working end-to-end pipeline` — verified message/block handling, added a **local
  sandbox backend** so the loop is testable without a container runtime. First real
  solve (a base64 warm-up).
- `Deterministic recon pass` — a cheap `ls/file/strings` step that briefs the
  specialist and sharpens routing. Cut the smoke test from 3 turns to 2.

## Phase 2 — Real benchmark, and a bug that mattered

- `InterCode-CTF importer` — 100 picoCTF-based tasks with ground-truth flags.
- **`Fix flag leak`** — the first batch scored a suspicious 11/11. Root cause:
  `challenge.json` (holding the gold flag) sat in the agent's working dir and recon
  was reading the answer. Restructured so the agent sees only a `files/` subdir;
  metadata + gold stay outside the sandbox. This is the single most important
  commit — it's the difference between a real benchmark and a worthless one.
- Added **near-miss scoring** (cracked-but-mis-formatted, tracked separately) and a
  **crash-safe** runner.

## Phase 3 — Measured iteration (the core FDE loop)

Each of these is: observe a failure mode → fix → re-measure a gain.

- **Crypto 9/19 → 13/19.** The auto-terminator was firing on rot13 flag look-alikes
  (`cvpbPGS{...}` matched the loose regex, stopping before decoding). Pinned the
  flag pattern to `picoCTF{...}`. +4 verified solves.
- **Rev 6/10 → 8/10.** Tightened flag extraction to reject whitespace/backtick
  "prose about the flag" the model emitted.
- **Placeholder rejection** — stopped accepting `picoCTF{...}` / `{your_flag_here}`.
- Honest per-category numbers recorded: forensics 9/10, general 8/8.

## Phase 4 — Faster + broader

- `Parallel runner` (`--concurrency`) — 38 challenges in ~15 min instead of serial.
- **Zero-turn fast-path** — if recon already surfaced the flag, solve with no LLM
  call. `Retry-on-fail` and cracking tools (rockyou/fcrackzip/pdfcrack) added.
- `Category-aware recon probes` (checksec, tshark, zsteg, exif, archive listing).
- `Six expert specialists` upgraded to tactical decision-tree playbooks.

## Phase 5 — Infrastructure reality

Honest about the messy parts (all fixed and recorded):
- Colima on Apple Silicon: Docker 29's containerd/overlayfs threw
  `UtimesNanoAt: input/output error` → switched to the `overlay2` driver.
- Disk exhaustion mid-build (hit 0 bytes); reclaimed ~16G of own footprint, routed
  around a harness that couldn't even write output.
- **Login-shell PATH bug** — `bash -lc` reset PATH from `/etc/profile`, hiding
  go/cargo/pipx tools (ffuf, nuclei, maigret) from the agent. Symlinked them onto
  `/usr/local/bin`.
- SageMath (no Kali pkg) and pwntools→unicorn (needs cmake / py3.13 filebytes)
  handled with best-effort layers so the image always builds.

## Phase 6 — Security posture

- **Per-category network isolation** — untrusted pwn/rev/forensics binaries run
  `--network none` (verified they can't reach the internet); web/osint/llm get
  network to authorised targets only.

## Phase 7 — Real-world validation

- **Live SSTI → RCE** — pointed the web specialist at a live vulnerable app (no
  local files). It recon'd, found `/greet`, confirmed SSTI, escalated to RCE, read
  the flag (11 turns), and wrote a clean report.
- **Live SQLi** — UNION column-counting, `sqlmap` orchestration, then recognised a
  boolean-blind oracle and hand-wrote a binary-search extractor (24 turns).

## Phase 8 — OWASP coverage

- **OWASP Web Top 10: 7/7 demonstrable categories exploited** (IDOR, crypto/
  integrity, SQLi, command injection, misconfig, JWT alg:none, SSRF) via
  `owasp_bench.sh`.
- **OWASP LLM Top 10:** added an `llm` specialist. **LLM06 Excessive Agency
  exploited** (tool abuse). Direct + indirect prompt injection (LLM01/02/07):
  **the target model defended** and returned decoy flags — reported honestly.
  Also caught and fixed a methodology flaw: the local backend let the agent read
  the target's source, so LLM demos were moved to the FS-isolated Docker backend.

## Phase 9 — Authorized real-world framework

- `scope.py` + `bounty.py` — a hard authorization guardrail: the agent refuses any
  target not explicitly authorized and in-scope (with an always-deny list for
  metadata endpoints / .gov / .mil), plus rate-limit config and a findings-metrics
  ledger. Real programs plug in only after the operator confirms automation is
  permitted and declares scope.

## How to reproduce

```bash
./.venv/bin/python test_ctf_agent.py            # logic-core unit tests
python run.py challenges/intercode --per-category 8 --concurrency 5 --retries 1
./owasp_bench.sh                                 # OWASP web coverage
./demo_live.sh                                   # live SSTI + SQLi exploitation
```

Full deliverables: `REPORT.md` (findings), `docs/owasp_coverage.md` (matrix),
`docs/*_writeup.md` (agent-generated exploit writeups), `STATUS.md` (raw log).
