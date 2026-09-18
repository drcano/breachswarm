# Stealth Engineering — Clean Lethality, Not a Bull in a China Shop

A scanner that hammers a target gets a finding *and* an instant blocklist entry.
Real programs treat volume as hostile (NBA: ">3 req/s is a DoS"; REI prohibits DoS).
Detected-and-shut-down lethality is worth zero. This is the work to make the agent a
ninja: get in, confirm the vuln, leave — minimal footprint, no overstep.

## The problem, measured (Fortress stress target)

The lethality test succeeded (opus solved the full 4-stage chain) but was **loud**:

| | Bull (baseline) |
|---|---|
| Total requests | **572** (for ~8 real endpoints) |
| Success ratio | **7.9%** (45 × 200; the other 92% were errors) |
| Tarpit `/api/legacy` | **190 hits** (an endpoint that always 500s) |
| 500 / 404 / 401 / 403 | 205 / 155 / 106 / 55 |

Root causes: wordlist/`for`-loop endpoint spraying, re-probing dead endpoints, no
dead-end detector in bounty mode, and payload-variant spray.

## The fixes (grounded in exactly those failures)

1. **Low-footprint directive** (BOUNTY_SYS): no wordlist/for-loop spraying; one
   hypothesis-driven request over payload spray; never re-probe an errored endpoint;
   stop once a vuln is confirmed.
2. **Dead-end detector wired into bounty mode** (it was solver-only).
3. **Per-endpoint circuit breaker**: after an endpoint errors 3×, real traffic to it
   is refused (synthetic "circuit-open" note) — true stealth, the requests never leave.
4. **Footprint metric** in the run ledger (tool_calls / error_results / circuit_blocks)
   so stealth is measurable, not vibes.

## Result — before → after (same target, same model, same chain)

| Metric | Bull | Ninja | Δ |
|---|---|---|---|
| Total requests | 572 | **119** | **−79%** |
| Tarpit hits | 190 | **6** | **−97%** |
| Success ratio | 7.9% | **29%** | ~4× cleaner |
| Turns / cost | 139 / $8.9 | 100 / $7.1 | leaner |
| **Full chain solved** | ✅ | ✅ | **lethality preserved** |

Stealth cost **zero** lethality: still reached `flag{f0rtr3ss_ch41n_5sti_after_ssrf_pwn}`,
5 findings, decoys rejected.

## Honest remaining gap

~49 WAF-403s remain — the agent still spray-tests bypass variants on the SSRF (37×)
and SQLi endpoints before landing the working evasion. The circuit breaker misses
these because a `403 blocked` response has a clean body (no error markers). And note
the real tension: **discovering a filter bypass inherently needs some trial-and-error**
— the evasion that makes it lethal is intrinsically a little noisy.

Next lever: key the circuit breaker on **HTTP status** (`curl -w "%{http_code}"`), so
403/404 spray trips it too. Plus the roadmap: passive-first recon, a hard per-finding
request budget, adaptive backoff on escalating blocks, timing jitter.

## Design principles (the assassin's discipline)

1. Recon before engagement (passive signals before active probes).
2. One strike, not a thousand cuts (hypothesis → the right request).
3. Never touch a tripwire twice (dead ends/tarpits/decoys abandoned).
4. Stay within the walls (scope-enforced egress, rate discipline, nothing destructive).
5. Take the objective and leave (stop once confirmed).
6. The only trace is the report.
