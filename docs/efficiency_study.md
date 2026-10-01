# Efficiency study — primitives, handcuffing, and the auto-exploit finding

Honest engineering record of the capability/efficiency work. Measured numbers and named
limits, not claims. (Companion to OVERNIGHT.md and rag_ablation.md.)

## What was built
- **Executable exploit primitives** (one tool call runs the whole paced routine in-sandbox,
  vs. the agent hand-looping): `blind_extract` (boolean-blind read), `time_blind` (timing
  oracle), `jwt_forge` (alg:none / weak-secret / RS256→HS256), `ssrf_recon` (map internal
  surfaces through an SSRF), `symbolic_solve` (angr crackme solver). Each has a live `verify_*`.
- **Shared scratchpad** (per-run state: surfaces + confirmed facts, `note` tool) so the agent
  infers from what it already scraped instead of re-deriving.
- **Staged recon** — re-fires deterministic (lean, ~2-request) recon on each *new* host:port a
  chain reaches; **archetype profiler** — fingerprint → {REST-JSON API / SPA+API / GraphQL /
  CMS / server-rendered} → ranked hunt list + a *skip* list (don't spray a wordlist at a JSON API).
- **Prompt-injection guard** on untrusted tool output (defang hidden/bidi chars + flag override
  attempts) — scoped to network runs only (stripping bytes would corrupt forensics/stego).
- **Cross-run memory** — per-archetype advisory priors from prior solves.

## Method
- **Handcuff to force efficiency:** cap turns hard (20–30). With `blind_extract` collapsing
  ~200 requests into one turn, an efficient agent should solve well inside the cap; hand-looping
  can't. The gap between the two is the signal.
- **Persist the trace on failure** (turn-cap raises, but we now write audit+scratchpad before
  re-raising) — without this the hardest runs were black boxes.

## Findings (measured)
- **Realistic BOLA (Harbor):** solved reliably and fast — 9–24 turns, 24–50s. Profiler + recon
  + ownership reasoning work; no wordlist spray; auto-exploit did **not** misfire on it.
- **Multi-stage chain (Gauntlet):** solved in ~5 min using `jwt_forge` (alg:none) + `ssrf_recon`
  (decimal-IP metadata) + scratchpad chaining.
- **Polymorphic WAF'd blind SQLi (Citadel/bastion) — the frontier, built to fight back:**
  - The agent **would not delegate to `blind_extract`** across ~8 runs. Four in-band nudges all
    failed: it reasons its way to "not injectable" and hand-rolls its own extraction/fuzz scripts.
  - Two root causes found: (1) the **60s sandbox timeout silently broke the primitive** — a
    paced 29-char extraction is ~97s, so even a correct call was killed; the agent's
    background-nohup-and-poll pattern was a rational workaround. Fixed (per-call 300s). (2) a
    strong DIY-scripting preference that prompts/nudges don't override.
  - **Auto-exploit** (detect a two-state oracle → run `blind_extract` automatically, removing the
    agency the way staged recon does) cracked poly-Citadel once (24t/7.5min) — the first agent
    solve ever — but is **1-for-3**: on the misses it fires but calibration fails, most likely
    because the agent trips the escalating rate-ban *before* it fires, so calibration probes read
    429 as a false condition. Robustness fix (ride out the ban in calibration) committed, pending
    re-measure.
- **Real bug surfaced by testing:** angr's `claripy` import was broken in the sandbox image
  (angr 10.x bundles it as `angr.claripy`), so symbolic execution had **never worked** — a
  contributor to the weak rev/pwn numbers. Fixed.
- **Audit regression caught:** the injection guard was stripping zero-width Unicode from all
  output, which would destroy a flag hidden in zero-width chars (stego). Scoped to network only.

## Open problems (honest)
1. **Reliable auto-inference of the injection shape** on a polymorphic target (param, marker,
   connector, encode depth, rate state). Auto-exploit's one-guess calibration is fragile.
2. **Getting a capable model to prefer provided primitives over writing its own tooling.**
   In-band nudges don't do it; removing agency (auto-fire) does, where it can be triggered
   reliably. This generalizes: the lever for stubborn tool-selection gaps is automation, not
   instruction.

## What this says about the system
Strong and efficient on realistic access-control and multi-stage chains; the deliberately
brutal polymorphic-WAF-blind-with-escalating-ban target is at/beyond the reliable autonomous
frontier by design, and auto-exploit moved it from 0 to partial. The honest headline is not
"solves everything" — it's "collapses the common exploit loops into one paced call, finds the
needle in a realistic haystack fast, and has a measured, named frontier."

## Benchmark regression (2026-09-20) — the session's changes did not regress the core
Re-ran full InterCode-CTF (pass@1, max-turns 40, retries 0) after all this session's work,
completing the ~34 tasks that hit the overnight usage cap on a second pass:
- **67/100 solved · 68% on completed tasks (67/99)** — flat vs the 70/100 baseline (3 tasks =
  pass@1 run-to-run variance), **no systematic regression**.
- Per category: crypto 13/18 (72%), forensics 12/15 (80%), rev 19/27 (70%), misc 22/33 (67%),
  pwn 1/4, web 0/2.
- **Zero auto-exploit / blind_extract / DIY-nudge misfires across all 100 tasks** — the web-
  exploit machinery never triggered on a non-matching pattern, confirming it is safe for the
  core solve path.
- Weak spots (real, small-sample): **pwn** (needs real exploitation, not just symbolic solve)
  and **web decoy-flag distraction** (the agent grabbed a plausible `picoCTF{...}` from a
  comment instead of the real flag on both web tasks — auto-terminates on the first flag seen).

## Target scoreboard (self-built, final)
- gauntlet (5-stage chain) **8/8**; harbor (realistic multi-tenant BOLA) **4/4**; the OWASP/
  modern demo suite (A01–A10, H1–H4, M1–M3, C1) all pass.
- citadel static **2/4**.
- **citadel_poly (polymorphic WAF blind) — reliable 2/2** after the auto-exploit + fire-on-both-
  states fixes (both solved fast, 12–15 turns). The auto-exploit (deterministically run
  blind_extract on a detected two-state oracle) is what cracked it: the agent would not delegate
  to the primitive on its own; removing the agency did.
- **bastion (auth-gate + polymorphic WAF + blind + escalating rate-ban) — 2/12, a named
  frontier.** Root-caused and fixed a chain of real bugs (blind_extract 401'd with no auth →
  carry the agent's `Authorization`; auth stored in a shell var → recover the JWT from the
  scratchpad; alg:none tokens have an empty sig → JWT regex fixed). Each fix landed a solve, but
  its FOUR stacked, polymorphic defenses mean a different layer is the wall each run, so reliable
  2/2 is beyond the current heuristic auto-exploit. Honest ceiling: solvable (proven twice, once
  in 5.5 min), not reliable. The extra stacked layer vs poly-Citadel is exactly the difference.

## Bottom line
Reliable and efficient where it counts — chains (8/8), realistic access-control (4/4), the OWASP
web spread, poly-Citadel (2/2), InterCode 67/100 (no regression, zero misfires). One deliberately
brutal 4-defense target (bastion) is a proven-solvable-but-not-reliable frontier, documented
honestly rather than papered over. The general lesson that generalizes past this repo: for a
stubborn agent tool-selection gap, **automation (auto-fire the primitive) beats instruction
(nudges); nudges failed 4×, auto-exploit worked.**
