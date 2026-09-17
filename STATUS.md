# Overnight status — 2026-09-17

Morning summary of what got built, what the numbers are, and what's blocked.

## TL;DR

The multi-agent CTF solver works end-to-end and produced a **real, uncontaminated
number** on the InterCode-CTF benchmark, on the two categories runnable without
the Docker toolset (crypto = full 19-challenge category; general = 8 sampled):

| Category | Strict solve | Effective (incl. near-miss) |
|---|---|---|
| Crypto (full category) | 9/19 (47%) | 11/19 (58%) |
| General Skills (8 sampled) | 8/8 (100%) | 8/8 (100%) |
| **Total** | **17/27 (63%)** | **19/27 (70%)** |

Real solves included small-N RSA, large-e RSA, triple-RSA, X.509 cert parsing,
Caesar/ROT, Vigenère, and transposition. Every run left an `audit.jsonl` +
`writeup.md`. For context, published agents score ~22% on the harder NYU-CTF /
Cybench sets; InterCode (picoCTF) is easier, so ~47% on a full crypto category is
a sane, honest baseline to iterate from.

"Near-miss" = solver cracked it but got the flag case wrong (classical ciphers
output UPPERCASE; picoCTF gold is often lowercase). Tracked separately, not
counted as a solve.

## Failure analysis (the useful part)

Crypto misses cluster into clear, fixable modes — exactly what to attack next:
- **ROT13 reported un-decoded** (tasks 5, 90, 96): the agent recognized ROT13 but
  printed the *ciphertext* `cvpbPGS{...}` instead of applying the rotation. Same
  bug three times → a targeted prompt/tool fix.
- **Uncracked hashes** (73, 86-adjacent): needs hashcat/john + wordlist, which the
  local backend lacks — will improve on the Docker image.
- **Placeholder flags** (74, 95, 57): agent emitted `picoCTF{...}` / example text
  instead of a real result — should count as "gave up," and a stricter
  find_flag could reject obvious placeholders.
- **Case-only near-miss** (55, 56): cracked, wrong case (see above).

General Skills went 8/8 (base conversions, strings, grep, netcat-style, disasm
teaser) — the agent is strong on straightforward tool-use tasks.

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

1. **Free disk** (~10–20G), build `Dockerfile.lean`, run forensics + rev on the
   Docker backend — the two categories most gated on the toolset.
2. Fix the **ROT13-not-applied** failure mode — highest-value crypto fix (3 tasks).
3. Run the full general-skills set (33) for a firmer number there.
4. Expand the image (Ghidra/pwntools/Playwright) for rev/pwn/web.
5. Case near-miss is left as-is: content case is genuinely unknowable to the
   solver and chasing it is benchmark-gaming; the near-miss column reports it.

Raw results: `results.local.jsonl` (27 challenges). Per-challenge writeups:
`challenges/intercode/<id>/writeup.md`.
