# What Pays in Bug Bounties — Patterns Distilled from Disclosed Reports

Source: public, already-aggregated disclosure datasets (chiefly
`reddelexc/hackerone-reports` — thousands of disclosed HackerOne reports
categorized by bug type and by bounty; ~$3.5M+ tracked payouts). We did **not**
scrape HackerOne/Bugcrowd directly (ToS + bot-detection). This is the signal we
used to make the `web` specialist more lethal (see `specialists.py`).

## The meta-finding: chains pay, single bugs don't

Reports earning **$20K+** are almost always **multi-stage chains**, not one bug:
`SSRF → cloud metadata → creds → RCE`, `import feature → path traversal →
execution`, `OAuth misconfig → account takeover across a partner ecosystem`.
Takeaway for the agent: after any primitive, **ask "what does this chain into?"**
before reporting.

## Top recurring high-bounty classes

| Rank signal | Class | What makes it pay |
|---|---|---|
| 🔴 highest | **SSRF → metadata → RCE/creds** | url/import/webhook/render params reaching `169.254.169.254` or internal admin (k8s/jenkins/grafana) |
| 🔴 | **Account takeover** | password-reset flaws (token entropy/expiry, host-header injection, link valid after email change), OAuth state/redirect_uri, JWT sig validation |
| 🔴 | **IDOR / BOLA** | swap object ids across users/tenants; method override; the single most common high-severity web bug |
| 🟠 | **RCE via deserialization / unsafe file processing** | PHP object cookies, ExifTool/ImageMagick, template/markdown render chains |
| 🟠 | **SQLi in legacy/filter params** | `countryFilter[]`, reporting endpoints; time/boolean-blind |
| 🟠 | **Business logic** | negative/fractional price & quantity, coupon/refund reuse, race conditions, workflow-step skipping |
| 🟠 | **Mass assignment / excessive data exposure** | POST extra `role`/`is_admin`/`verified`; over-returned PII & tokens |
| 🟡 | **GraphQL** | introspection → hidden queries/mutations, node-id IDOR, alias-batching to bypass rate limits |
| 🟡 | **Path traversal → file read/write → RCE** | uploads/importers/rewriters |
| 🟡 | **Credential leakage in CI/CD artifacts** | tokens in git history, build artifacts (GitHub token report = $50K) |

## Per-class technique checklists (now baked into the web specialist)

**IDOR / BOLA** — for every `user_id`/`order_id`/file id/GraphQL node id: swap for
another user's & another tenant's; method override (GET→PUT/DELETE); unauth access
to "protected" routes; bulk/batch ops; ownership must be checked *per request*.

**SSRF** — trigger surfaces: file/image/PDF renderers, webhooks, url/import/preview
params. Targets: `169.254.169.254/latest/meta-data/`, localhost 8080/9090/3000,
docker/k8s/jenkins. Filter bypass: IPv6, decimal IP, DNS-rebind, double-encode.
Always try to chain to creds/RCE.

**Account takeover** — reset token entropy/expiry; reset link valid after email
change; host-header injection in reset; OAuth state param + redirect_uri allowlist
bypass; JWT alg:none / key confusion / weak secret; email change without
re-auth.

**Business logic** — negative/zero/fractional quantity & price; coupon/refund
reuse; skip workflow steps; concurrent requests (race) on balance/redeem/transfer.

**Mass assignment / excessive data** — inject `role`,`is_admin`,`verified`,
`balance` on POST/PUT; scan responses for over-returned PII/tokens.

**GraphQL** — `{__schema{...}}` introspection → hidden queries/mutations, call
unauth; node-global-id IDOR; alias-batch to bypass rate limits; nested-query DoS.

**API (REST)** — BOLA first; excessive data exposure; mass assignment;
unauthenticated internal endpoints; verb/version tampering; secrets in responses.

## How this changed the system

- `specialists.py` `web` playbook rewritten around these money classes, ordered by
  real payout (IDOR/SSRF/mass-assignment/business-logic/GraphQL now explicit
  steps, not afterthoughts).
- Reinforces existing targets that already model these: `targets/owasp_web.py`
  (SSRF, JWT), `targets/hard_app.py` (mass-assignment→admin, IDOR-after-auth,
  business logic, filter-evasion SQLi), `targets/modern_app.py` (GraphQL, NoSQLi,
  XXE) — our lab already exercises most of the top classes.

## Experiment: a prompt-level "chain-aware step" did NOT cut turns (negative result)

Hypothesis: telling the specialist to chase a primitive's pivot before widening
would cut the wasted turns seen on the chain target (baseline 20 turns). Measured on
`C1_ssrf_chain`, one run per config:

| Config | Turns | Note |
|---|---|---|
| No directive (baseline) | **20** | breadth found the loopback pivot fast |
| Broad "chase one chain to its end before widening" | **50** | **backfired** — fixated on the leaked token, burned ~40 turns hunting where to use it (vault/s3/hostnames/ports) instead of the loopback |
| Refined "try a leaked cred on already-seen surface first" | **24** | fixed the fixation but ≈ baseline; no real gain within run-to-run noise |

Conclusion: the broad directive is actively harmful (suppresses the breadth that
finds the pivot); the refined one is neutral. **Reverted both** — shipping a neutral
change as a win would be dishonest. Cutting turns likely needs a *structural* change,
not a prompt line: e.g. a dead-end detector that widens after N failed same-dimension
probes, or a dedicated pivot tool. Single-run variance is high here — any real claim
needs multi-run measurement.

## Structural dead-end detector (prototype, shipped)

The prompt experiment failed because it acted on *intent*; this acts on *outcomes*.
`solver._sandbox_server` wraps every tool result with `_stall_nudge`: it classifies
each result as productive or a dead-end (`_is_unproductive`: empty, or ≥2 error
markers with no success marker; a flag is always productive) and, when **≥4 of the
last 6** results are dead-ends, appends an in-band "step back and widen" note (with a
3-turn cooldown so it doesn't nag). Deterministic, unit-tested, no change to the
query loop.

Design note — why a *sliding window*, not a consecutive counter: the first cut
counted strictly-consecutive failures and **never fired** — agents intersperse one
good probe to dodge it (observed max streak = 3 while ~10 of 24 commands were dead
ends). Density-over-window catches the real interspersed-fixation pattern.

Validation (cost-free replay over the real 42-turn fixation trace): the detector
**would fire at command #11 and #15** — mid-fixation, while the agent was burning
turns guessing metadata/vault/hostnames, well before it found the loopback pivot.
So the mechanism triggers on the actual pathology.

Honest limit: whether the injected note *reduces* turns live is **not yet proven** —
turn counts on this target are variance-dominated (observed 20 / 24 / 42 / 50 across
single runs), so any turn-cut claim needs multi-run measurement. What is proven: the
detector fires on the real dead-end pattern and bounds runaway same-dimension probing.

## Next lethality upgrades (candidates)

1. **Multi-run measurement harness** to quantify the detector's turn effect against
   variance (the missing piece for a real turns-cut claim).
2. **Race-condition tooling** in the web specialist (concurrent request helper).
3. A **BOLA sweeper**: given an authenticated session + an object-id param,
   auto-swap ids across a second identity.


## Validation — the upgrade chains on its own

Built a harder target that requires the top-payer chain (`targets/chain_app.py`,
run via `chain_bench.sh`): **SSRF → cloud metadata (169.254.169.254) → leaked IAM
creds → internal localhost-only admin → flag**. No single request wins; direct
admin access is 403 (internal-only).

The upgraded `web` specialist **solved it autonomously in 20 turns / 73.5s** — the
audit trail shows it probing `/preview` for SSRF, hitting the metadata service,
reading `iam/security-credentials/s3-backup-role`, extracting the Vault token, and
pivoting back to the internal admin endpoint. Those metadata/credential probes come
straight from the new playbook. Evidence: `results/chain.jsonl`.
