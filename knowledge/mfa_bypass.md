## MFA / 2FA Bypass — 7 patterns (pays ATO without a prior session)
After username+password you hold a partial/`pre-mfa` session. Attack the second factor; each pattern
below is High/Critical when it yields account takeover.

1. No rate limit on OTP → brute force. 6-digit = 1M space; fuzz `/api/verify-otp` with `seq -w 000000 999999`,
   filter 400/429, throttle (`-t 5`) since aggressive rates trip lockout/ban. No lockout + no rate limit = ATO.

2. OTP not invalidated after use → sniff/observe one code, reuse it on a later login (or after logout).
   If the same `123456` is accepted twice, the code never expires = persistent hijack.

3. Response manipulation (client-side-only check) → submit a wrong OTP, intercept the response, flip
   `{"success":false}`→`true` (or `401`→`200`), forward. If the app proceeds, the server trusted the client.

4. Skip the MFA step (workflow bypass) → the pre-mfa cookie/session already grants access. Go straight to
   the post-auth resource: `curl -b "session=PRE_MFA" https://t/dashboard`. Access without the `/mfa/verify`
   step = auth-flow bypass = Critical. Also: complete MFA in one session, reuse that cookie in another
   browser (checks whether completion is bound to the session).

5. Race on verification → send the same OTP simultaneously (single-packet / asyncio.gather). If two parallel
   `/mfa/verify` both succeed = parallel-session ATO / one-code-many-uses. See [[race_condition]].

6. Backup-code brute force → 8-char alphanumeric is too big, but many apps use 6-8 DIGIT backup codes
   (1-10M, feasible with no rate limit) at `/verify-backup-code`. Also test reuse after exhaustion and
   predictable regeneration.

7. "Remember this device" trust escalation → complete MFA once on your box, capture the remember-device
   cookie, replay it from a new IP/UA. If MFA is skipped, device trust isn't bound to IP/UA = ATO anywhere.

Adjacent: OTP delivered in the API response body or a header; predictable timestamp-based codes; MFA
enrollment IDOR (enroll your authenticator on the victim's account). Rate-limit bypass tricks (endpoint
variation, GraphQL alias batching = 100 attempts/request) feed pattern 1 — see [[waf_bypass_payloads]].
Report the exact bypassed step and prove full login without the legitimate second factor. See [[auth_reset_oauth]].
