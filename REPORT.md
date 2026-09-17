# CTF Agent — Findings Report

A multi-agent system that autonomously solves capture-the-flag (CTF) challenges,
built on the Claude Agent SDK and benchmarked on InterCode-CTF. This report covers
what was built, how it was measured, the results, and what was learned.

Repo: `github.com/drcano/ctf-agent` · Companion visual doc: `docs/how-it-works.html`

---

## 1. What it is

An orchestrator routes a challenge to one of six category specialists (crypto,
reversing, pwn, web, forensics, misc/general). A deterministic **recon** pass runs
first to gather facts and sharpen routing; each specialist drives real security
tools inside an isolated **sandbox**; a deterministic **verifier** stops the loop
the instant a correctly-formatted flag appears. Every run produces a timestamped
**audit log** and an LLM-written **writeup**.

The design is deliberately not "one big agent." It follows a finding from the CTF-agent
literature (EnIGMA, D-CIPHER): the *tool interface* and clean measurement matter more
than orchestration cleverness. So the build invests in scoped tools, per-challenge
isolation, and honest scoring.

## 2. Methodology

- **Benchmark:** InterCode-CTF — 100 picoCTF-derived tasks with ground-truth flags,
  spanning all six categories.
- **Scoring:** *strict* = exact match to the gold flag (the same check picoCTF runs).
  A separate *near-miss* column marks challenges the solver cracked but mis-formatted
  (e.g. classical ciphers output uppercase; gold is lowercase). Near-misses are
  **never** counted as solves.
- **Auto-termination:** the verifier regex-matches the flag format on every command's
  output and stops immediately — the main cost control.
- **Sandboxes:** two backends. *Docker* = one Kali container per challenge (real
  isolation; Rosetta runs x86-64 on the M1). *local* = host shell (no isolation;
  trusted crypto/general only, used when a container isn't available).

### A leak we caught and fixed

The very first batch scored a suspicious 11/11. Cause: the `challenge.json` metadata
file — which contains the gold flag — was sitting in the agent's working directory,
and the recon `strings` pass was reading the answer straight out of it. Every "solve"
was contaminated.

Fixed by restructuring every challenge so the agent sees only a `files/` subdir;
metadata and gold live in the parent, outside the sandbox. All numbers below are the
uncontaminated, post-fix results. (This is the difference between a credible benchmark
and a worthless one.)

## 3. Results

**Balanced 6-category run** (full toolset image, expert prompts, expanded recon,
retries; 38 tasks, ran in 1164s at concurrency 5):

| Category | Strict | Notes |
|---|---|---|
| General Skills | 8/8 (100%) | base conv, strings, grep, scripting |
| Forensics | 7/8 (88%) | steg, pcap, metadata, carving |
| Reversing | 6/8 (75%) | static analysis + simple logic |
| Crypto | 5/8 (63%) | RSA, classical, hashes |
| Pwn | 1/4 (25%) | some need a live remote service |
| Web | 0/2 (0%) | **live servers offline — see below** |
| **Total** | **27/38 (71%)** | 75% excluding the dead-server web tasks |

**Deeper per-category runs** (larger samples): Crypto **13/19 (68%)** full category;
Forensics **9/10 (90%)**; Reversing **8/10 (80%)**.

### A real limitation, named honestly

The two Web tasks (and some Pwn) point at **live picoCTF servers**
(`jupiter.challenges.picoctf.org`, `mercury.picoctf.net:34561`) with no local
files. Those hosts are long decommissioned and the offline sandbox has no route to
them — so Web 0/2 is a **dataset/harness limitation, not a solver weakness**. On
self-contained challenges the effective rate is ~75%+. This is exactly the class of
challenge the *real-world* platform (below) targets, against live authorised hosts.

Real solves include small-N RSA, large-e RSA, triple-RSA, X.509 certificate parsing,
Caesar/ROT, Vigenère, and transposition ciphers; plus base conversions, `strings`,
`grep`, and disassembly teasers in general skills. For context, published agents score
~22% on the harder NYU-CTF / Cybench sets; InterCode (picoCTF) is easier, so these are
a sane baseline to iterate from.

### Measured improvement in one iteration: crypto 9/19 → 13/19

The auto-terminator was firing on encoded flag look-alikes: a ROT13-encoded
`cvpbPGS{...}` matched the loose default flag regex, so the solver stopped *before*
decoding it. Three crypto tasks failed this exact way. Pinning the flag pattern to
`picoCTF{...}` fixed it — verified +4 strict solves. Find the failure mode, fix it,
re-measure the gain.

## 4. Failure analysis

- **Placeholder flags** — the agent sometimes emits `picoCTF{...}` (literal) or an
  example flag instead of a real result; should be treated as "gave up," and a
  stricter flag check can reject obvious placeholders.
- **Multi-line parsing** — a base64 flag split across lines was mis-stitched; a
  robustness gap in output handling, not reasoning.
- **Case near-miss** — cracked but wrong case. Content case is genuinely unknowable to
  the solver, so it is reported honestly rather than gamed.
- **(fixed) ROT13-not-decoded** — see the improvement above.

## 4b. Real-world validation — live SSTI exploit

To prove the platform works beyond static CTF files, a deliberately-vulnerable
Flask app (`targets/vuln_app.py`) was stood up as a live service and the **web
specialist pointed at it with no local files** — exactly the bug-bounty setup.

It autonomously, in 11 turns:
1. Recon'd the homepage (`curl -is`), fingerprinted Flask/Werkzeug, and spotted a
   "debug greeter" hint in an HTML comment.
2. Brute-forced endpoint names and found `/greet`.
3. Confirmed Jinja2 SSTI (`{{7*7}}` → `49`).
4. Escalated to **SSTI remote code execution**
   (`{{ cycler.__init__.__globals__.os.popen(...) }}`) to run shell commands on the
   target, read the app source/config, and exfiltrate the flag.

It then produced a clean, publishable writeup of the whole chain
(`docs/ssti_demo_writeup.md`). Reproduce with `./demo_live.sh`. This is the same
loop that applies to authorised bug-bounty targets and security research.

## 5. Infrastructure notes

- **Runtime:** Colima on Apple Silicon (M1) with `--vm-type vz --vz-rosetta` so x86-64
  binaries run. Docker must use the `overlay2` storage driver, **not** the containerd
  snapshotter — Docker 29's containerd/overlayfs on Colima throws
  `UtimesNanoAt: input/output error` and corrupts builds. Set
  `{"features":{"containerd-snapshotter":false}}` in the VM's `daemon.json`.
- **Images:** `Dockerfile.lean` (crypto/forensics/rev, ~2.6GB, fast) and
  `Dockerfile.agent` (full toolset). SageMath has no Kali apt package (deferred);
  pwntools→unicorn needs cmake (deferred to the full image).
- **Disk:** the full-toolset builds are large; a constrained disk was the main
  practical blocker during development.

## 6. What's built vs. deferred

**Working:** orchestrator, recon, verifier, both sandboxes, audit + writeup, crash-safe
batch runner, near-miss scoring, InterCode importer, crypto/forensics/rev tools.

**Deferred by design (add when a batch shows the need):** stateful MCP tools —
GhidraMCP (rev), pwndbg-mcp (pwn), Playwright (web); the full image's heavy tools;
LLM-based category fallback and an LLM critic in the verifier.

## 7. Next steps

1. Fix the placeholder-flag acceptance (stricter `find_flag`).
2. Wire GhidraMCP + Playwright for the rev/web categories, then re-measure.
3. Scale beyond samples to the full 100-task benchmark for a firm headline number.
4. Publish the auto-generated writeups as a public portfolio artifact.
