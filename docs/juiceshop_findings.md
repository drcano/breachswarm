# Vulnerability Assessment — OWASP Juice Shop (http://172.17.0.2:3000)

## Executive Summary

Authenticated, read-only testing against the authorized instance confirmed two Critical SQL injection flaws — one grants instant admin login, the other dumps every user's email and password hash — plus a High-severity IDOR exposing other customers' baskets and a null-byte filter bypass that serves blocked files. Several information-exposure issues (confidential docs, an open metrics endpoint, an over-scoped auth-details endpoint, verbose SQL errors) round out the findings. Root causes cluster on non-parameterized DB queries, missing server-side authorization, and serving sensitive files/endpoints without access control.

| # | Finding | Severity | CWE |
|---|---------|----------|-----|
| 1 | SQL injection auth bypass in `POST /rest/user/login` | Critical | CWE-89 |
| 2 | UNION SQL injection in `GET /rest/products/search` (full credential dump) | Critical | CWE-89 |
| 3 | Poison null-byte file-filter bypass in `GET /ftp/` | High | CWE-22 |
| 4 | IDOR in `GET /rest/basket/{id}` | High | CWE-639 |
| 5 | Excessive data exposure in `GET /rest/user/authentication-details` | Medium | CWE-639 |
| 6 | Confidential document served unauthenticated (`/ftp/acquisitions.md`) | Medium | CWE-16 |
| 7 | Unauthenticated metrics endpoint (`/metrics`) | Medium | CWE-16 |
| 8 | Verbose SQL error leakage in product search | Low | CWE-209 |

---

### 1. SQL Injection in `POST /rest/user/login` allows full authentication bypass

- **Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)
- **CWE:** CWE-89 (SQL Injection)
- **Affected asset:** `POST http://172.17.0.2:3000/rest/user/login`, JSON field `email`
- **Summary:** The login query concatenates the `email` value directly into SQL. An attacker logs in as the administrator with no valid password, giving complete control of the application.
- **Steps to Reproduce:**
  1. Send:
     ```
     POST /rest/user/login HTTP/1.1
     Content-Type: application/json

     {"email":"' OR 1=1--","password":"x"}
     ```
  2. Observed response: a valid JWT is returned. Decoding its payload shows `"id":1, "email":"admin@juice-sh.op", "role":"admin"` — authenticated as the administrator without credentials.
- **Impact:** Full administrative account takeover; access to all privileged functionality and data.
- **Remediation:** Use parameterized queries / ORM parameter binding for the login lookup; never concatenate request input into SQL.
- **References:** https://cwe.mitre.org/data/definitions/89.html · OWASP A03:2021 – Injection

---

### 2. UNION-based SQL Injection in `GET /rest/products/search` allows full credential database exfiltration

- **Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)
- **CWE:** CWE-89 (SQL Injection)
- **Affected asset:** `GET http://172.17.0.2:3000/rest/products/search`, parameter `q`
- **Summary:** The product search parameter is injectable and supports UNION queries, letting an unauthenticated attacker read arbitrary tables including the full user table.
- **Steps to Reproduce:**
  1. Request:
     ```
     GET /rest/products/search?q=qwert'))%20UNION%20SELECT%20email,password,3,4,5,6,7,8,9%20FROM%20Users--
     ```
  2. Observed response returned every user's email and password hash in the `data` array, e.g.:
     ```
     {"id":"admin@juice-sh.op","name":"0192023a7bbd73250516f069df18b500", ...}
     {"id":"accountant@juice-sh.op","name":"963e10f92a70b4b463220cb4c5d636dc", ...}
     ```
- **Impact:** Disclosure of the entire user credential store. The hashes are **unsalted MD5** (chainable weakness), so they are trivially crackable/rainbow-tableable, enabling mass account takeover and credential-stuffing against other services.
- **Remediation:** Use parameterized queries for the search lookup; separately, migrate password storage to a salted adaptive hash (bcrypt/argon2/scrypt).
- **References:** https://cwe.mitre.org/data/definitions/89.html · OWASP A03:2021 – Injection

---

### 3. Poison Null-Byte in `GET /ftp/` allows retrieval of blocked files

- **Severity:** High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)
- **CWE:** CWE-22 (Improper Limitation of a Pathname / path traversal via null byte)
- **Affected asset:** `GET http://172.17.0.2:3000/ftp/<file>%2500.md`
- **Summary:** The `/ftp` handler blocks sensitive extensions (`.bak`, `.gg`, `.yml`, `.pyc`) but the check runs before null-byte truncation, so appending `%2500.md` bypasses it and serves the protected file.
- **Steps to Reproduce:**
  1. Direct request `GET /ftp/package.json.bak` → **403 Forbidden** (also `coupons_2013.md.bak`, `eastere.gg`, `encrypt.pyc`, `suspicious_errors.yml` → 403).
  2. Bypass request `GET /ftp/package.json.bak%2500.md` → **200 OK**, returning the backup source:
     ```
     { "name": "juice-shop", "version": "6.2.0-SNAPSHOT", ... }
     ```
  3. `GET /ftp/coupons_2013.md.bak%2500.md` → 200, returning the (encrypted) coupon-code file contents.
- **Impact:** Access to files the application explicitly attempts to protect — backups, source metadata, and encrypted coupon data (which can be cracked offline for free-product coupons).
- **Remediation:** Reject requests containing null bytes; validate the fully resolved filename against a strict extension allowlist after all decoding/truncation.
- **References:** https://cwe.mitre.org/data/definitions/22.html · OWASP A01:2021 – Broken Access Control

---

### 4. IDOR in `GET /rest/basket/{id}` allows reading other users' baskets

- **Severity:** High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5)
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Affected asset:** `GET http://172.17.0.2:3000/rest/basket/{id}`
- **Summary:** The basket endpoint returns any basket by ID without checking ownership, exposing other customers' cart contents.
- **Steps to Reproduce:**
  1. Authenticate (any session token; the trace used the id-1 token from Finding 1).
  2. Request `GET /rest/basket/2` with that token.
  3. Observed response returned basket id 2 belonging to a different account: `{"status":"success","data":{"id":2,"UserId":2, ... "Products":[{"id":4,"name":"Raspberry Juice (1000ml)", ...}]}}`.
- **Impact:** Horizontal privilege escalation — an attacker enumerates basket IDs to read other customers' purchase data.
- **Remediation:** Enforce `basket.UserId === session.userId` server-side before returning any basket.
- **References:** https://cwe.mitre.org/data/definitions/639.html · OWASP A01:2021 – Broken Access Control

---

### 5. Excessive data exposure in `GET /rest/user/authentication-details`

- **Severity:** Medium — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5)
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Affected asset:** `GET http://172.17.0.2:3000/rest/user/authentication-details`
- **Summary:** The endpoint returns authentication details for every user rather than only the caller, leaking the full account roster.
- **Steps to Reproduce:**
  1. Request the endpoint with a valid session token.
  2. Observed response contained **23** user records (verified by counting `"email"` fields), including `admin@juice-sh.op`, `jim@juice-sh.op`, `bender@juice-sh.op`.
- **Impact:** Enumeration of all registered accounts, useful for targeting the SQLi/credential findings above.
- **Remediation:** Scope the response strictly to the authenticated user's own record.
- **References:** https://cwe.mitre.org/data/definitions/639.html · OWASP A01:2021 – Broken Access Control

---

### 6. Confidential document served without authentication (`/ftp/acquisitions.md`)

- **Severity:** Medium — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)
- **CWE:** CWE-16 (Configuration) / sensitive data exposure
- **Affected asset:** `GET http://172.17.0.2:3000/ftp/acquisitions.md`
- **Summary:** A document marked confidential is served to anyone, unauthenticated.
- **Steps to Reproduce:**
  1. `GET /ftp/acquisitions.md` → 200 OK.
  2. Observed body: *"# Planned Acquisitions > This document is confidential! Do not distribute! Our company plans to acquire several competitors within the next year. This will have a significant stock market impact…"*
- **Impact:** Disclosure of market-sensitive business information; potential insider-trading / reputational exposure.
- **Remediation:** Remove sensitive files from the publicly served `ftp` directory and gate the path behind authorization.
- **References:** https://cwe.mitre.org/data/definitions/16.html · OWASP A05:2021 – Security Misconfiguration

---

### 7. Unauthenticated metrics endpoint (`/metrics`)

- **Severity:** Medium — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)
- **CWE:** CWE-16 (Configuration)
- **Affected asset:** `GET http://172.17.0.2:3000/metrics`
- **Summary:** Prometheus metrics are exposed publicly, leaking operational internals.
- **Steps to Reproduce:**
  1. `GET /metrics` → 200 OK (no auth).
  2. Observed output includes internal counters such as `juiceshop_llm_input_tokens_total`, `juiceshop_llm_output_tokens_total`, and HELP metadata.
- **Impact:** Information disclosure of internal usage/behavior; aids reconnaissance and can leak business-sensitive volume data.
- **Remediation:** Restrict `/metrics` to the internal network or require authentication.
- **References:** https://cwe.mitre.org/data/definitions/16.html · OWASP A05:2021 – Security Misconfiguration

---

### 8. Verbose SQL error leakage in product search

- **Severity:** Low — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (5.3, adjusted down for limited detail)
- **CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)
- **Affected asset:** `GET http://172.17.0.2:3000/rest/products/search?q=`
- **Summary:** A malformed injection payload triggers an unhandled error and HTTP 500, confirming injectability and aiding attack tuning.
- **Steps to Reproduce:**
  1. `GET /rest/products/search?q=test'` → HTTP 500 Internal Server Error (unhandled SQL error).
- **Impact:** Confirms the injection point and provides DB-error feedback that speeds exploitation of Finding 2.
- **Remediation:** Return generic error responses; suppress database error detail in production. (Resolved at root by fixing Finding 2.)
- **References:** https://cwe.mitre.org/data/definitions/209.html · OWASP A05:2021 – Security Misconfiguration

---

## Coordinated Disclosure

This assessment was performed against an authorized, self-hosted instance; testing was read-only, respected rate limits (~8 req/s), and made no destructive changes. Please do not publicly disclose these findings before a fix is deployed. Standard 90-day disclosure window applies; happy to re-test and coordinate timing after remediation.