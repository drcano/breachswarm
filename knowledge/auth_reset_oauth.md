## Authentication: Password Reset & OAuth Flaws
Password reset:
- Host-header injection: `Host: evil.com` (or `X-Forwarded-Host: evil.com`) -> reset link in the email points to your host -> victim clicks -> token leaks to you.
- Token weakness: sequential/short/predictable tokens, no expiry, reusable, not invalidated after use or after email change; brute a 4-6 digit code (no rate limit).
- Response leakage: reset API returns the token/link in the JSON response or redirect.
- Account takeover via email change then reset; parameter pollution `email=victim@x.com&email=attacker@x.com`; array `email[]=`.
- IDOR on reset: change `user_id`/`email` in the reset-confirm request to reset someone else's password.
OAuth / SSO:
- `redirect_uri` not strictly validated -> point to attacker host, steal `code`/`access_token` (see open_redirect) -> ATO.
- Missing/replayable `state` -> login CSRF / account linking to attacker.
- `response_type=token` implicit leak via referer/history; pre-account-connection takeover.
- Steal `code` via open redirect / referer / XSS on the callback origin; reuse authorization code.
JWT session issues: see jwt card (alg:none, key confusion, weak secret).
Escalate: full account takeover. Report the exact leaked token path.
