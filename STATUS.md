# Overnight status — 2026-09-17

Morning summary of what got built, what the numbers are, and what's blocked.

## TL;DR

The multi-agent CTF solver works end-to-end and produced a **real, uncontaminated
first number** on the InterCode-CTF benchmark, on the two categories runnable
without the Docker toolset:

| Category | Strict solve | Effective (incl. near-miss) |
|---|---|---|
| Crypto | 5/8 (62%) | 8/8 (100%) |
| General Skills | 8/8 (100%) | 8/8 (100%) |
| **Total** | **13/16 (81%)** | **16/16 (100%)** |

Avg 3.8 turns/solve. Real solves included small-N RSA, large-e RSA, X.509 cert
parsing, Caesar, Vigenère, and Morse. Every run left an `audit.jsonl` + a
`writeup.md`.

"Near-miss" = the solver cracked the cipher but got the flag case wrong
(classical ciphers output UPPERCASE; picoCTF gold is lowercase). Tracked
separately and honestly — it's a real, fixable formatting gap, not a solve.

## Important bug I caught and fixed

The first batch scored **11/11 (100%)** — too good. Cause: `challenge.json`
(which holds the gold flag) was sitting in the agent's working directory, and the
recon `strings` pass was reading the answer straight out of it. **Leak.**

Fixed by restructuring every challenge so the agent only sees a `files/` subdir;
metadata + gold live in the parent, outside the sandbox. Re-ran uncontaminated →
the honest 13/16 above. (This is the difference between a credible benchmark and
a worthless one, and it's exactly the kind of rigor the writeup should highlight.)

## What was built tonight

- Verified everything against `claude-agent-sdk` 0.2.154 (real API, not guessed).
- Recon pass (your idea) wired in — deterministic `ls/file/strings`, feeds routing
  + briefs the specialist. Cuts wasted turns.
- Near-miss scoring; strict stays the headline.
- Hardened the batch runner: one challenge's error (or a writeup failure) no
  longer kills the run; partial results are flushed crash-safe.
- InterCode-CTF imported: 100 challenges, gold safely out of the sandbox.
- Colima runtime brought up with Rosetta (x86-64 works on the M1).

## What's blocked — needs your call

**Disk.** Your Mac's data volume is 429G used of 460G. Tonight the repeated
full-Kali Docker builds filled it completely (builds silently failed, and at one
point the disk hit 0 bytes free and no command could even write output). I
reclaimed **~16G** of my own footprint (deleted the 15G Colima VM + pip/brew
caches), which got things moving again — but there's only ~1.7G free now.

Consequences:
- **Docker builds don't fit.** The lean image (~1.5G) and the full toolset image
  can't build until there's more free space. So **forensics / reverse / pwn / web**
  (which need the Kali toolset + isolation) are **not yet run**.
- Tonight's numbers came from the **local backend** (host Python, no container).
  Safe here because these are public picoCTF practice challenges, but the local
  backend is crypto/general only and unsafe for untrusted binaries — those must
  wait for Docker.

**To unblock:** free up disk (even ~10–20G lets the lean image build and opens up
forensics/rev). Then: `docker build -t ctf-agent:latest -f Dockerfile.lean .`
and run `python run.py challenges/intercode --per-category 5 --max-turns 25`.

## Infra notes / gotchas recorded

- Colima needs `overlay2`, not the containerd snapshotter: Docker 29's containerd
  image store + overlayfs on Colima's VM throws `UtimesNanoAt input/output error`
  and corrupts the build. Fixed via `/etc/docker/daemon.json`
  `{"features":{"containerd-snapshotter":false}}`. The lean Dockerfile builds fine
  once there's disk.
- macOS has no `timeout`; use background + bounded waits.
- SageMath has no Kali apt package (deferred); `pwntools`→`unicorn` needs cmake
  (deferred to the full image).

## Suggested next steps (in order)

1. Free disk, build `Dockerfile.lean`, run forensics + rev on the Docker backend.
2. Scale the crypto/general run to the full set for a firmer number.
3. Fix the case-formatting near-miss (small prompt tweak) — turns 3 near-misses
   into strict solves.
4. Then expand the image (Ghidra/pwntools/Playwright) for rev/pwn/web.

Raw results: `results.local.jsonl`. Per-challenge writeups: `challenges/intercode/<id>/writeup.md`.
