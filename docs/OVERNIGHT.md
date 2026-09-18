# Overnight run — build log & results

Session goal (your brief): build a premier RAG, improve each agent's speed/functionality,
enable agent-to-agent interaction for chained exploits, and research/collect data on
authorized targets. Speculative mode ON; honest measurement kept throughout.

Everything below is committed on `main` with per-change commits so you can read the
history top to bottom. Green state: `test_ctf_agent.py` 9/9, `eval_rag.py`, per-module
self-checks all pass.

---

## 1. Premier RAG — 9 → 32 cards, measured
The knowledge base was web-only (9 cards). It's now a full offensive corpus across
**every specialist** plus a dedicated exploit-**chains** playbook.

- **Corpus:** 35 card files → 37 retrievable chunks (see `docs/knowledge_coverage.md`).
  New: command injection, LFI/traversal, deserialization, GraphQL, XSS, open redirect,
  CORS, request smuggling, race conditions, NoSQLi, prototype pollution,
  auth/reset/OAuth, subdomain-takeover/cache-poisoning, business logic, secrets/recon
  exposure, CSRF, RSA, padding-oracle, hash/classical crypto, ROP, format-string/heap,
  reversing, stego, pcap/memory, archive-cracking, and **chains**.
- **Measurement harness (`eval_rag.py`):** 28 realistic queries, reports recall@1/@3,
  asserts no regression as cards grow.
  - Before: **recall@1 8/25, recall@3 12/25** (9 web cards).
  - After:  **recall@1 26/28, recall@3 28/28** (37 chunks).
- **Null result (honest):** tried a **BM25** retriever (k1=1.5, b=0.75). It *regressed*
  — "code execution from a template" saturated toward the pwn cards and lost the SSTI
  card at rank-1. Kept TF-IDF + heading boost; documented in `knowledge_base.py`.

## 2. Recon → playbook loop (best-in-class recon, acted on)
Recon already fingerprints the target; now it *acts* on that. `recon.playbook_text()`
maps the fingerprint to the right cards and **pre-loads them into the specialist's
brief** before it fires a single exploit request:
- Werkzeug/Flask → SSTI; Node/Express → prototype-pollution + NoSQLi; PHP → LFI/wrappers;
  `/graphql` → GraphQL; `.git`/`.env` → source disclosure; plus per-category defaults
  (pwn→ROP, crypto→RSA, forensics→stego) and the money-bug set for any web target.
- Fingerprint-scoped (top ~4 cards) so the prompt stays lean; env-gated (`CTF_PLAYBOOK=0`)
  for A/B. This is the "walk in with a plan" behavior you kept asking for.

## 3. Multi-agent exploit orchestrator (the "exploit agent on top")
Built `orchestrator.py`: a lead exploit agent that **plans a kill chain and delegates
each stage** to fresh web-specialist sub-agents (nested SDK `query()` loops) sharing one
sandbox, carrying discovered artifacts (tokens/keys/URLs/roles) forward on a blackboard
(`run_specialist` / `record_artifact` tools). Hypothesis: fresh sub-contexts resist the
long-context fixation a single agent hits on deep chains.

**Kept only if it wins** (your call). Head-to-head harness: `bench_orchestrator.py`
(baseline `solver.solve` vs orchestrator, same target/flag/sandbox/RAG).

### A/B results — Fortress (4 stages) & Gauntlet (5 stages)
Three modes, same target/flag/sandbox/RAG. Budgets: baseline & stateful = 40 SDK turns;
orchestrator = 24 orchestrator-turns × up to 16 per delegated sub-agent (≈10× the
effective budget — noted so the cost is read honestly, not as a like-for-like turn count).

Primary metric is **wall-clock** (fully captured for every run; correlates with cost).
`sdk_cost` is token-based SDK cost; it reads `0` for baseline/stateful **solves** because
those early-exit on the flag *before* the SDK's usage-bearing final message — a side effect
of the cost-saving auto-terminate. The orchestrator doesn't early-exit, so its cost is real.
turns count streamed AssistantMessages (~2.5× the SDK turn cap), consistent across modes.

| target | mode | solved | avg turns | avg wall s | notes |
|---|---|---|---|---|---|
| **Gauntlet** (5-stage) | baseline | **2/2** | 54 | **187** | fastest; early-exit |
| | stateful | **2/2** | 41 | 164 | ≈ baseline (within N=2 noise) |
| | orchestrator | **1/2** | 92 | 637* | *avg mixes a 280s **solve** + a 993s **fail**; $1.70–2.78/run |
| **Fortress** (4-stage) | baseline | 0/2 | 40 | 1167 | validation run *did* solve (~1030s): solvable, high-variance |
| | stateful | 0/2 | 102 | 1010 | $2.2–2.9/run |
| | orchestrator | 0/1 | 134 | 2817 | **2.4× wall, $6.51/run** |

**Findings:**
- **The orchestrator did not win.** It never beat baseline on solve rate (Gauntlet 1/2 vs
  2/2 at N=2; Fortress 0/1 vs a baseline that solved in validation) and it always cost real
  time/$ where the single agents early-exit for ~nothing. Per-outcome (the honest cut, since
  averaging solve+fail runs is misleading): its one Gauntlet *solve* took 280s ≈ **1.5×** a
  baseline solve **and** cost $1.70; its failing runs are very expensive (Gauntlet 993s;
  Fortress 2817s / $6.51). Fresh sub-contexts *re-pay* recon/decoy cost each delegation and
  hand off lossily — overhead with no upside here. (N=2 is small; the cost/latency gap is the
  robust result, the solve-rate delta is suggestive.)
- **Explicit state (stateful) merely tied baseline** (2/2 both on Gauntlet, wall within
  noise). The extra machinery didn't earn its keep either — a single context already
  remembers its own artifacts across a 5-stage chain.
- **Depth ≠ difficulty.** The *deeper* Gauntlet (5 stages) was solved in ~3 min while the
  *shallower* Fortress (4 stages) mostly failed — because per-stage **technique** difficulty
  dominates. Gauntlet's stages (IDOR, NoSQLi `$ne`, JWT `alg:none`, decimal-IP SSRF, cmdi)
  map cleanly onto RAG cards and execute directly; Fortress's **S1 WAF-evasion SQLi +
  `information_schema` enumeration** (335 requests across 3 runs) is the real wall. This is
  **consistent with the RAG carrying real load** (clean technique→card mapping = fast solves)
  — though not yet *isolated*: recon-playbook and the base model are confounds, so a direct
  RAG ablation (next-step #2) is what would prove it. It also pinpoints where to harden
  guidance next (WAF-evasion methodology).

**Verdict (measure-first, kept-only-if-it-wins):** neither the multi-agent orchestrator nor
the explicit-state layer beat a single well-equipped agent (RAG + recon-playbook). **Baseline
stays the default.** `orchestrator.py` and `stateful.py` are retained as documented, opt-in
experiments with their honest negative/neutral results — not wired into the default path.
This is the point: the fancy architecture was *measured*, not assumed, and rejected on data.

## 4. New harder target: Gauntlet (5-stage chain)
`targets/gauntlet_app.py` — IDOR → NoSQLi (operator injection) → JWT `alg:none` forge →
SSRF (decimal-IP egress bypass) → command injection → RCE/flag. Deeper than Fortress to
discriminate single- vs multi-agent on a long chain, and it exercises the new cards end
to end. `targets/verify_gauntlet.py` proves the full solve path (all 5 stages → real
flag) so the A/B runs against a known-good target.

## 5. Three real bugs the A/B harness caught (the harness as a fuzzer)
Running the experiment turned the solve loop into a stress test and surfaced three genuine
bugs — the two logic bugs (#1, #3) have regression tests in `test_ctf_agent.py`; #2 is a
harness-robustness wrap mirroring `run.py`'s existing handling (no unit test):

1. **Silent-decoy flail (correctness).** With the decoy-rejection fix in place, the agent
   found the `/api/debug` honeypot flag, the loop silently refused it, but *nothing told
   the agent* — so it re-fetched `/api/debug` **50×** and never progressed past S1. Fix:
   `_decoy_nudge` appends explicit "KNOWN DECOY, do not re-fetch" feedback to any tool
   result containing a self-labeled decoy (wired into every sandbox tool). After the fix:
   **1 decoy hit** instead of 50, and the agent walks the chain. Correct on real honeypots
   too.
2. **Crash on budget exhaustion (robustness).** `solver.solve()` *raises* on max_turns
   (SDK `ResultError`); the bench didn't catch it, so a budget-exhausted baseline crashed
   the whole matrix. Fix: the harness records max-turns as a clean `solved=False`
   non-solve. (`run.py`, the main benchmark path, already handled this — `solve()` left
   unchanged so the 70/100 max-turns exclusion semantics are untouched.)
3. **False-positive flag detection (correctness).** The chain solvers called `find_flag()`
   with no pattern, so the loose fallback regex matched `args{name}` in agent output and
   auto-terminated on garbage. Fix: thread the strict `flag{…}` pattern through
   `solve_stateful`/`solve_chain`/`run_specialist` so all modes detect flags identically.

The decoy fix also generalizes: `flag.py` now rejects self-announcing decoys
(`notthereal`/`decoy`/`honeypot`/…) target-agnostically, so it protects live runs where the
decoy string can't be known in advance.

## 6. Data collection & targets research
`docs/targets.md`: vetted authorized targets — self-hosted for data collection
(Juice Shop/crAPI/DVGA/VAmPI/Pixi/DVWA…), public sanctioned (vulnweb family), CTF corpora
for RAG mining, and the two notable automation-permitting bounty programs (Shopify,
Google VRP) with a qualify-before-run checklist. Per your go-ahead, tonight's live runs
are local + vulnweb only.

---

## Spend
Rough **~$30–40** (SDK cost; only partially captured — baseline/stateful *solves* early-exit
before the usage-bearing message, so their cost reads 0). The orchestrator dominated spend:
$6.51 (Fortress) + $1.70 + $2.78 (Gauntlet) + $2.27 (pilot) ≈ **$13 for 4 runs** vs the
single agents' ~free solves — itself part of the verdict.

## Ranked "do next"
1. **Harden the measured bottleneck: S1 WAF-evasion recon.** The data pins failures on
   WAF-evasion SQLi + `information_schema` enumeration. Add a WAF-probe to `_web_recon`
   (send a blocked payload, detect the 403/"blocked" signature) and force-load the
   `waf_evasion`+`sqli` cards when a WAF is detected. Highest expected ROI.
2. **Quantify the RAG's contribution (ablation A/B).** The depth≠difficulty finding implies
   the RAG is doing real work; measure it: baseline with `CTF_PLAYBOOK=0` and/or
   `search_knowledge` removed vs full, on Gauntlet. Turn the intuition into a number.
3. **Right-size the single-agent budget for deep chains.** Fortress is solvable but
   high-variance at 40 turns; test 55–60 turns (or better early-stage efficiency) so deep
   chains solve reliably without the orchestrator's cost.
4. **Fix cost capture on early-exit solves** so every run has a token-cost number (drain to
   the final ResultMessage, or accumulate per-message usage) — closes the one measurement
   gap in this A/B.
5. **Real-app data runs:** stand up crAPI + DVGA + Pixi (see `docs/targets.md`) to exercise
   the new API/GraphQL/NoSQL/mass-assignment cards on apps the system has never seen.
6. **Authorized bounty go-live** when a program that permits automation is in hand
   (`docs/GO_LIVE.md`), with `--enforce` egress + rate limiting.

## What did NOT make the cut (measured & rejected — the honest part)
- **Multi-agent orchestrator** — fewer solves, 3.4× wall, real cost. Kept opt-in, documented.
- **Explicit-state (stateful) agent** — tied baseline, no win. Kept opt-in, documented.
- **BM25 retriever** — regressed vs TF-IDF+heading-boost on this corpus. Reverted.
- (Prior sessions: chain-aware prompt, dead-end detector, parallel-recon — all null/negative,
  already documented in `docs/bounty_patterns.md`.)
