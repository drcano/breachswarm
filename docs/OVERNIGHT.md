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

- **Corpus:** 32 card files → 34 retrievable chunks (see `docs/knowledge_coverage.md`).
  New: command injection, LFI/traversal, deserialization, GraphQL, XSS, open redirect,
  CORS, request smuggling, race conditions, NoSQLi, prototype pollution,
  auth/reset/OAuth, subdomain-takeover/cache-poisoning, RSA, padding-oracle,
  hash/classical crypto, ROP, format-string/heap, reversing, stego, pcap/memory,
  archive-cracking, and **chains**.
- **Measurement harness (`eval_rag.py`):** 25 realistic queries, reports recall@1/@3,
  asserts no regression as cards grow.
  - Before: **recall@1 8/25, recall@3 12/25** (9 web cards).
  - After:  **recall@1 23/25, recall@3 25/25** (34 chunks).
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
> _Filled from the run below._ **[RESULTS PENDING — see §6]**

## 4. New harder target: Gauntlet (5-stage chain)
`targets/gauntlet_app.py` — IDOR → NoSQLi (operator injection) → JWT `alg:none` forge →
SSRF (decimal-IP egress bypass) → command injection → RCE/flag. Deeper than Fortress to
discriminate single- vs multi-agent on a long chain, and it exercises the new cards end
to end. `targets/verify_gauntlet.py` proves the full solve path (all 5 stages → real
flag) so the A/B runs against a known-good target.

## 5. Correctness fix found via a run: self-labeling decoys
A Fortress A/B run showed the solver **auto-terminating on the `/api/debug` honeypot**
flag (`flag{debug_endpoint_not_the_real_flag}`). `flag.py` now rejects self-announcing
decoys (`notthereal`/`decoy`/`honeypot`/…) as a normalized substring — target-agnostic
(needs no hardcoded per-target string, so it protects live runs too). Test added.

## 6. Data collection & targets research
`docs/targets.md`: vetted authorized targets — self-hosted for data collection
(Juice Shop/crAPI/DVGA/VAmPI/Pixi/DVWA…), public sanctioned (vulnweb family), CTF corpora
for RAG mining, and the two notable automation-permitting bounty programs (Shopify,
Google VRP) with a qualify-before-run checklist. Per your go-ahead, tonight's live runs
are local + vulnweb only.

---

## Spend & ranked "do next"
> _Filled at the end._
