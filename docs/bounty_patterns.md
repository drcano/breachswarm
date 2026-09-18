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

## Next lethality upgrades (candidates)

1. A **chain-aware verifier prompt**: after a primitive, force the "what does this
   chain into?" step before concluding.
2. **Race-condition tooling** in the web specialist (concurrent request helper).
3. A **BOLA sweeper**: given an authenticated session + an object-id param,
   auto-swap ids across a second identity.
