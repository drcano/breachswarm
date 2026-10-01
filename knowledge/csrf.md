## CSRF — Cross-Site Request Forgery
Where: any state-changing request (change email/password, transfer, add admin, connect
account, update settings) that relies only on cookies for auth.
Detect: remove/alter the CSRF token and the anti-CSRF header — does the request still
succeed? Check `SameSite` on the session cookie (None/absent = cross-site sends cookies).
Token weaknesses to try:
- Token not validated when absent (delete the `csrf` param/header entirely).
- Token not tied to the session (use your own valid token against the victim).
- Static/predictable token, or token in a cookie only (double-submit that reflects a
  cookie you can set).
- Method bypass: endpoint accepts GET for a state change, or method-override
  (`_method=POST`, `X-HTTP-Method-Override`).
- Content-type bypass: JSON endpoint also accepts `application/x-www-form-urlencoded` or
  `text/plain` (simple request, no preflight) -> classic form CSRF; or send JSON via
  `<form enctype="text/plain">` padding trick.
- Clickjacking assist: no `X-Frame-Options`/CSP frame-ancestors -> frame + UI-redress a
  state change.
PoC: an auto-submitting `<form action="https://target/change_email" method="POST">` on
attacker page, or `fetch(url,{method:'POST',credentials:'include',...})` when CORS/
SameSite allow. Login-CSRF and connect-account-CSRF are often overlooked.
Escalate: forced email/password change -> account takeover; add-admin; fund transfer.
Impact depends on the action — target the highest-value state change.
