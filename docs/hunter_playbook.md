# Hunter Playbook — making ctf-agent operate like the best bug hunters

Synthesized from 5 parallel research streams (2026-09-21): elite-hunter methodology, recon mastery,
high-value bug classes + chaining, AI/autonomous SOTA (XBOW/Big Sleep/ZeroPath/Strix), and the
success/failure meta-game. Sources are in the session transcript.

## Shipped — 2026-09-22 (discovery->verify loop closed)
The #1 lever (discovery breadth) is now largely built. New this session, all scope-guarded, all
run THROUGH the enforced sandbox->proxy, all no-op-if-tool-absent:
- `dast_scan` (nuclei -dast) — ACTIVE param fuzzing (reflected XSS/error-SQLi/LFI/SSTI/open-redirect/
  CRLF). nuclei already in image -> works NOW. Ceiling: OOB templates need interactsh (unreachable
  under --enforce) -> use `oob`.
- `crawl` (katana) — live-crawls to PARAM-BEARING URLs that feed dast_scan (static JS-mining only
  gives route names). NEEDS IMAGE REBUILD.
- `secret_scan` (trufflehog --only-verified) — verified leaked creds in the target's JS; a hit is a
  WORKING key, not regex noise. NEEDS IMAGE REBUILD.
- `authz_matrix` id-transform — forges the victim's neighbor id in the endpoint's OWN encoding
  (int/hex/base64/GraphQL global-node base64("Type:123")); single non-owner 2xx on a neighbor = BOLA.
- Loop guardrails — `repeat_guard` (exact-repeat: nudge@3, refuse@5, error-independent) + `--wall-cap`
  wall-clock budget (research: cost<->success correlate inversely, so stop a non-converging run).
Pipeline now: subdomain_recon -> crawl -> secret_scan -> endpoint_recon -> dast_scan -> primitives
-> chain_scan, kept efficient by the guardrails.
ACTION: `docker build -t ctf-agent:latest -f Dockerfile.agent .` to activate katana + trufflehog.

STILL OPEN (the heavier next phase, each needs a decision):
- Authenticated-browser SESSION mode (#13) — real Playwright persistent-context build (Chrome
  --dump-dom can't carry a bearer/cookie session; not a one-liner). The #2 lever (auth context).
- Benchmark harness (#6) — needs targets (XBOW's 104 dockers / PortSwigger labs); how we MEASURE.
- More arsenal (subfinder/httpx/jsluice/gau/puredns) — each a clean Dockerfile line + no-op wiring.
- BOLA write-path + mass-assignment; variant analysis (seed known-CVE, hunt siblings).

## The verdict (all 5 streams converge)
Our problem was never exploits or safety — those are already XBOW-shaped. It is four compounding
things: **wrong targets, narrow discovery, shallow/unauthenticated depth, no chaining.** We ran a
disciplined verifier, shallow and logged-out, against two of the hardest programs alive.
Finding nothing was the *expected* result.

## What actually wins
- **XBOW** (topped HackerOne US): edge = recon-at-scale → target scoring → fan-out of many
  short-lived single-objective solvers, gated by **deterministic, blind validators**. "Creative AI
  discovers; deterministic logic decides." 200 zero-days, 0 false positives via planted canaries.
  Better orchestration, not better exploits.
- **Top humans:** first-mover on fresh scope; weeks of authenticated depth on ONE target;
  understand-before-attack (docs → the dev's false assumptions); hunt IDOR/access-control/logic (not
  commodity XSS/SQLi); and CHAIN low-sevs into crits.

## Keep (already SOTA-shaped — do not rebuild)
blind_extract/time_blind (calibrated oracles), oob collaborator, browser_verify (headless DOM),
canary tokens, the slop/negative-gating validator, campaign memory, lead backlog, enforced sandbox.

## Build roadmap (priority = payout-per-build)

STRATEGIC (aim + depth — cheap, highest ROI):
- [ ] **1. Freshness monitor** — pivot discover.py into a scope-diff daemon: baseline program list +
      per-program scopes/subdomains; trigger a hunt the hour a NEW program/asset/feature appears.
      First-mover on un-picked surface is the one axis where our speed beats humans.
- [ ] **2. Understand phase** — parse docs/Swagger/OpenAPI/JS → structured app-model (endpoints,
      roles, stated constraints "only admin can X" = the map of missing checks). Gate primitives on it.
- [ ] **3. Authenticated multi-account depth** — drive real browser SESSIONS + a creds-set
      abstraction; test post-login surface; promise-driven dwell, not a uniform turn budget.

ARCHITECTURAL (throughput + criticals):
- [ ] **4. Coordinator → scored fan-out → dedup** — enumerate full surface, score it, spawn many
      short-lived single-objective solvers (one class × one endpoint), retired per mission;
      SimHash+imagehash dedup BEFORE spending LLM turns.
- [ ] **5. Chain-finder** — "never report a primitive alone." Standing pass over confirmed leads
      matched to canonical templates (SSRF→metadata→creds, open-redirect→OAuth→ATO, IDOR→admin→RCE).
      Turns mediums into crits (10% → 25-40% crit/high).
- [ ] **6. Multi-account BOLA/BFLA engine** — upgrade authz_matrix: N sessions + response-diffing,
      write/action-level (not just read), ID-transform (base64/hash/UUID/GraphQL-node),
      mass-assignment, function-level matrix, new-endpoint priority. The #1 growth class.
- [ ] **7. Blind confidence-scored validator** — hand it {payload, effect, canary/OOB proof} with the
      agent's reasoning STRIPPED; confidence = oracle-pass + reproducibility − anti-slop; graduate ≥0.85.
- [ ] **8. More canary-backed verifiers + SSRF-escalation ladder** — XXE, path-traversal,
      cache-poisoning, .git/secret exposure; auto cloud-metadata probe on confirmed SSRF.
- [ ] **9. Recon breadth** — GitHub secret-dorking (TruffleHog, highest single-bounty yield), active
      DNS (puredns/alterx), favicon→Shodan origin pivot, source-maps, APK decompilation.
- [ ] **10. Model routing** — Haiku recon / Sonnet bulk / Opus chains + prompt caching, to make
      fan-out affordable inside the ≤3 concurrency budget.

## The honest limit
Business logic is the human frontier — even XBOW ships mostly injection/traversal/SSRF/secrets.
Do NOT claim autonomous logic. Instead borrow Big Sleep's move: **variant analysis** — seed solvers
with known-CVE patterns for the target's stack and hunt unpatched variants. Tractable, high-yield.

## Round-2 addendum — the definitive diagnosis (XBOW/MAPTA/OSS deep-dive)
"We built the mouth (verifier) but starved the eyes (discovery) and the memory (context/auth)."
Our verification skeleton IS the commodity — XBOW/Ethiack/Aardvark/NodeZero/MAPTA all converge on it,
and MAPTA proves ~77% of XBOW's own benchmark is reachable with PUBLIC models + this skeleton. So the
gap is NOT verification. Reprioritized, by impact:

1. [HIGHEST] DISCOVERY BREADTH — a Coordinator stage that maps the FULL surface (auth headless crawl,
   JS/route extraction via jsluice, param mining via Arjun, subdomain enum via subfinder/puredns,
   OpenAPI/Swagger ingestion, sitemap) BEFORE spawning solvers. Integrate the deterministic arsenal
   into the sandbox image behind egress_proxy --enforce + scope.py: ProjectDiscovery suite (pdtm:
   subfinder/dnsx/httpx/katana/naabu/nuclei/interactsh/alterx/mapcidr/asnmap/uncover/cdncheck),
   tomnomnom glue (anew/unfurl/qsreplace/gf), jsluice, trufflehog --only-verified, dalfox, ffuf/
   feroxbuster, puredns/massdns + SecLists/assetnote wordlists. nuclei -dast + interactsh is the single
   biggest verify unlock. Evaluate BBOT (importable Python recon engine) vs shelling out — spike first.
2. AUTHENTICATED + WHITE-BOX CONTEXT (XBOW "Assessment Guidance") — MAPTA 77% black-box vs 96% white-box
   on the SAME 104: the delta is CONTEXT. Intake creds/sessions + API specs + docs + source, fed to the
   coordinator and passed to solvers. We have --docs/--auth-env; extend to a session-holding browser.
3. VERIFIABLE BITES (cheapest high-value, ~1 day) — decompose each objective and validate every step
   (endpoint exists → object-ref exists → access persists logged-out → …), not hunt-then-validate.
4. PER-OBJECTIVE SOLVER FAN-OUT + detailed-technique prompting + Python payload-gen (one solver = one
   endpoint × one class with a playbook; generic prompts only test typical payloads).
5. LOOP GUARDRAILS + unified run budget (rounds/tokens/cost$/wall-clock; identical-call→reflection;
   hard caps) — from PentAGI/hackingBuddyGPT. Early-stop ~40 tool calls (MAPTA: cost↔success inversely
   correlate — a good solver wins fast or not at all).
6. BENCHMARK HARNESS to replace the flywheel we don't have — run vs XBOW's 104 validation-benchmarks +
   PortSwigger labs + an adversarial "Hallucinbot" FP harness. This is how we MEASURE progress.
7. Class depth: multi-account BOLA (write-path, ID-transform), variant analysis (seed known-CVE, hunt
   siblings — Big Sleep), nuclei -dast.

DO NOT: rebuild the validator (parity); thousands-of-agent orchestration + per-CWE dedup (premature);
model-routing/LiteLLM (Claude-SDK-only); try to replicate XBOW's HackerOne live-fire data flywheel —
that is the ONE advantage we structurally cannot copy; the benchmark harness (#6) is the honest substitute.

Adopt (pattern-level, no fork): dedicated Validation-gate + structured Reporter tool as the ONLY path
to emit a finding (MAPTA/Big Sleep); Strix (Apache-2.0) as the fork-able web-tooling reference; RAG-
ingest PayloadsAllTheThings/HowToHunt/nuclei-templates/tbhm.

## Anti-slop discipline (non-negotiable — programs are PAUSING bounties over AI slop)
Never report a primitive alone. Never let the LLM grade its own work. Verification is a deterministic
oracle pass on stripped evidence. One human review gate at final submission.

## MEASURED — 2026-09-22 (first bounty-pipeline benchmark)
`bench_bounty.py` runs the full bounty.hunt() pipeline vs our known-vuln targets, scored by ground
truth (planted-flag recovery + validator-graduated findings). First result, on ctf-agent:latest
(pre-katana/trufflehog image; crawl/secret_scan no-op'd — nuclei-dast, browser_session, authz_matrix
id-transform, chain_scan, loop-guardrails all live):

  find-rate 3/3 targets solved:
    harbor  (multi-tenant cross-tenant BOLA)          solved  16-19 turns  ~50s   1 validated High
    gauntlet(IDOR->NoSQLi->JWT->SSRF->RCE, 5 stages)  solved  35 turns    117s   6 validated
    chain   (SSRF->metadata->internal admin)          solved  34 turns    130s   2 validated
  ~$1-2.4/run. Reproducible (harbor solved twice).

The benchmark immediately earned its keep: it surfaced a validator FALSE-NEGATIVE (a correct harbor
BOLA report rejected because its section also documented the hardened sibling surfaces it probed);
root-caused + fixed (a recovered flag / achieved cross-boundary read now overrides the negative gate)
+ regression-tested. This is the build->measure->fix loop we were missing.

HONEST READ: real evidence of capability on realistic BOLA + multi-stage chains, fast + cheap, with
findings that graduate a strict validator. BUT: N=3, and these are OUR targets (possible teach-to-the-
test bias) — a controlled measurement, not proof vs the best on live external scope. Next: (a) widen
the bench (more targets + PortSwigger labs + an adversarial FP set), (b) a real scalp on fresh
authorized scope via the freshness monitor. Rebuild the image to put crawl/secret_scan in play.

## MEASURED #2 — 2026-09-22 (full toolset + advanced primitives)
Image rebuilt (katana/trufflehog/nuclei-dast/playwright-chromium all verified live). Added 5 advanced
exploit primitives (race / mass_assign / graphql / xxe / smuggle) -> 22 agent tools. Re-ran the bench
with everything live + a new SPA/XHR target (spa_app) that exercises the discovery tools:

  find-rate 4/4:  harbor 14t/42s (1 val)   gauntlet 16t/38s (5 val)
                  chain  13t/30s (3 val)   spa      24t/48s (1 val)  ~$1-1.4/run
  spa: agent mined app.js + /api/session to discover the non-HTML /api/v2/statements endpoint, then
  IDOR'd statement 2002 -> flag (the XHR/JS discovery path works end to end).

Exploit-tool coverage now spans the money classes: access-control/BOLA (authz_matrix +id-transform),
SSRF->metadata (ssrf_recon), injection (dast_scan/sqlmap/SSTImap), JWT (jwt_forge), blind
(blind/time), XSS incl. authenticated (browser_verify/session), secrets (secret_scan), race, mass-
assignment, graphql, xxe, smuggling. Remaining gaps: deserialization + prototype-pollution (no
dedicated primitive; via sandbox_bash). Still not yet proven on external live scope — N small, our targets.

## CEILING — 2026-09-22 (hard-target limit, honest)
Ran the pipeline vs the 3 hardest self-built targets (full toolset). Result: it does NOT solve the
hard multi-stage/WAF/blind targets within a ~20-min budget.
  boss (Fortress, 4-stage, hard stage-1 WAF)  NOT solved  107 turns / 1148s / $10.5  (0 validated)
  citadel (blind-only, WAF, rate-limited)      NOT solved   82 turns / 1232s          (0 validated)
  bastion (auth+WAF+blind frontier)            not run (stopped to save budget; historically ~2/12)
Key positive: on BOTH failed runs the validator graduated 0 findings — no false positives when the
pipeline doesn't actually break through (anti-slop holds under a losing run). So the honest picture:
solves realistic single/loosely-chained targets fast + cheap (4/4), but a hardened WAF'd multi-stage
target is still the ceiling — same frontier the CTF solver hit (boss/bastion). Budget note: max_turns
did NOT cap these (ran 80-107 "turns"); the --wall-cap was the real limiter -> wall-cap is the budget
control that matters, and hard targets cost ~$10/run to fail. Cheap wins fast; expensive loses slow.

## MEASURED #3 — 2026-09-22 (advanced primitives proven end-to-end)
Built 4 vuln targets for the new primitives and ran the bounty pipeline against them: 4/4 solved,
so the advanced tools are proven to actually FIND the bug, not just compile:
  race_app     (non-atomic one-time coupon)        solved 34t/182s  1 val  [race -> double-spend]
  massassign_app (profile PATCH binds role)         solved 15t/29s   1 val  [mass_assign -> admin]
  xxe_app      (lxml resolves external entities)     solved 10t/19s   3 val  [xxe -> file read]
  graphql_app  (introspection + user(id:) no authz)  solved 13t/25s   2 val  [graphql -> BOLA]
Running tally on self-built targets: 8/8 solved where the class is a single/loosely-chained web bug
(harbor, gauntlet, chain, spa, race, massassign, xxe, graphql); 0/2 on hardened WAF'd multi-stage
(boss, citadel). Exploit-tool coverage is now both COMPLETE (24 tools) and PROVEN for the web classes.
