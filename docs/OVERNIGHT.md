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

**Fortress (4-stage), measured:**

| mode | solved | avg turns* | avg cost $ | avg wall s |
|---|---|---|---|---|
| baseline | 0/2 | 40 | (n/a on fail) | 1167 |
| stateful | 0/2 | 102 | 2.58 | 1010 |
| orchestrator | 0/1 | 134 | **6.51** | **2817** |

*turns count streamed AssistantMessages (~2.5× the SDK turn cap), consistent across modes.
A separate validation baseline **did** solve Fortress (real flag, ~1030s), so the chain is
solvable at this budget — it's just high-variance right at the 40-turn edge.

**Read:** the orchestrator cost **~2.5× the wall-time and ~2.5× the $** of the stateful
single agent and solved no more often (none of the three cleared Fortress's S3/S4 endgame
within budget on these runs). Stage-hit analysis of the target's own access log shows the
bottleneck is **S1** (WAF-evasion SQLi + `information_schema` enumeration — 335 requests
across 3 runs) and the **S3 decimal-IP SSRF / S4 SSTI** endgame — not the coordination
layer. Fresh sub-contexts also *re-pay* recon/decoy cost each delegation.

**Gauntlet (5-stage): [PENDING — filling from the running matrix].**

**Verdict (measure-first, kept-only-if-it-wins): [FINALIZED AFTER GAUNTLET].** On Fortress
the multi-agent orchestrator did not earn its ~2.5× cost. Retained in-repo as a documented,
opt-in experiment with its honest result — not wired into the default path.

## 4. New harder target: Gauntlet (5-stage chain)
`targets/gauntlet_app.py` — IDOR → NoSQLi (operator injection) → JWT `alg:none` forge →
SSRF (decimal-IP egress bypass) → command injection → RCE/flag. Deeper than Fortress to
discriminate single- vs multi-agent on a long chain, and it exercises the new cards end
to end. `targets/verify_gauntlet.py` proves the full solve path (all 5 stages → real
flag) so the A/B runs against a known-good target.

## 5. Three real bugs the A/B harness caught (the harness as a fuzzer)
Running the experiment turned the solve loop into a stress test and surfaced three genuine
correctness bugs — each fixed with a regression test:

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

## Spend & ranked "do next"
> _Filled at the end._
