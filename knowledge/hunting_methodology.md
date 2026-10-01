## Hunting Methodology — the non-linear workflow and session discipline
Recon (recon_methodology.md) and chaining (chains.md) tell you WHAT to look at and how to combine
primitives. This card governs the LOOP: how a session is structured, when to pivot vs go deep, and
how to not burn time. Effective hunters aren't linear and aren't tireless — they are disciplined.

Session start — DEFINE, SELECT, EXECUTE (do this before touching a tool):
- DEFINE one goal for the session: Confidentiality (steal data) / Integrity (change data) /
  Availability / Account-Takeover / RCE. You are proving an attack scenario, not "finding a bug."
- SELECT 1-2 vuln classes to hunt (IDOR, race, business-logic, ...). Focus beats breadth.
- EXECUTE only those. "Just looking around" = wasted session.
- Fix identity up front: anon or authed? Load auth ONCE; reuse the exact session for every request.

The 5 phases are NON-LINEAR — RECON -> MAP -> FIND -> PROVE -> REPORT, but loop back on any block:
- New API/endpoint surfaces mid-test -> drop back to MAP it before attacking (never attack unmapped).
- WAF/403 wall at PROVE -> back to RECON for origin IP / alt host / soft-block bypass.
- FIND yields nothing -> rotate vuln class, don't grind one endpoint.
Each new privilege/surface re-fires recon on THAT surface with what you now hold (re-map as admin
once you forge a token).

Wide vs deep — pick per surface:
- WIDE (recon sweep): new program, wildcard `*.target` scope, scope just expanded. Cast for surface.
- DEEP (focused): known webapp you've mapped, an interesting subdomain, or hunting auth/IDOR/logic
  bugs (auth-aware, one flow at a time). Depth over breadth: one target understood > ten skimmed.

TIME DISCIPLINE (this is what separates a clean run from a token-burn):
- 5-MINUTE RULE: a surface showing nothing interesting after 5 min -> move on. Kill signals: all
  hosts 403 after a bypass attempt, static marketing pages, no ID-param APIs, no JS with real paths.
- 20-MINUTE ROTATION: every 20 min ask "am I making progress?" No -> rotate endpoint -> subdomain
  -> vuln class. Fresh context finds more than brute force.
- 45-MIN RABBIT-HOLE CAP: max ~45 min on one parameter. Stuck longer = you're stuck; log it and go.

Route the input to the class (FIND decision — don't spray, pick the applicable technique):
- ID param (user_id/order_id/node id) -> IDOR/BOLA.  Search/filter/sort -> SQLi/NoSQLi.
- URL/webhook/import/render param -> SSRF.  Reflected text -> XSS.  File upload -> shell/SVG/traversal.
- price/qty/coupon -> business logic + race.  login/2FA/reset -> auth bypass.  profile PUT -> mass-assign.
Probe-escalation ladder per input: error-based first (`'` `"` `{{7*7}}` `${7*7}`, watch 500/traces)
-> time-based (`sleep`) -> OOB (interactsh/DNS callback) -> boolean (content-length diff). Stop at first hit.

A confirmed bug is a SIGNAL, not a finish line (cluster-hunt before you write it up):
- SIBLING RULE: if `/api/user/123/orders` is vulnerable, hit `/export` `/delete` `/share` on the
  same object. Same dev, same sprint, same missing check — this explains ~1/3 of paid IDOR.
- A->B: one bug means the developer made a CLASS of mistake elsewhere. Time-box 20 min hunting B/C
  siblings; if none, submit A and move on. Report independent bugs SEPARATELY (separate payouts);
  only merge when one chain genuinely needs both.

Anomaly detection — the app tells on itself; log anything that "feels wrong" and revisit:
- Naming drift (`userId` everywhere, then one `user_id`) -> different dev -> weaker checks there.
- Error-shape diff (same 403, different JSON body) -> different backend -> boundary to probe.
- Version diff (a JS bundle changed) -> new endpoints / dropped params. NEW (<30 days) == UNREVIEWED.
- 200 with a tiny/"just a moment" body -> WAF soft-block, not a real response; confirm before trusting.

Where impact actually lives (bias the hunt here): FOLLOW THE MONEY — billing/credits/refund/wallet
is where devs cut corners (price manip, payment races, quota bypass). Prefer LESS-SATURATED classes
(cache poisoning, races, business logic, request smuggling, CI/CD) over saturated ones (basic XSS/
SSRF/open-redirect) unless target-specific. Impact > vuln class: score by business damage, not label.
(Skip-the-noise list and low-footprint discipline already live in bounty.py BOUNTY_SYS — obey them.)
