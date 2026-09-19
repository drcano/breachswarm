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
