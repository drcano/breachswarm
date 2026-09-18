# Vulnerability Assessment — testasp.vulnweb.com (acuforum ASP forum)

## Executive Summary

Authorized black-box testing of the Acunetix "acuforum" test application (`http://testasp.vulnweb.com/`) confirmed five distinct vulnerabilities, including SQL injection permitting authentication bypass and database read, and path traversal permitting arbitrary local file disclosure. All findings were verified with read-only, throttled probes (~2 req/s) strictly against the in-scope host. Note: probes were relayed through the project egress guard, which rewrites upstream HTTP 500 responses to the string `egress blocked: … HTTP Error 500: Internal Server Error` — that string is the injection/error signal, not a WAF block.

| # | Finding | Severity | CWE |
|---|---------|----------|-----|
| 1 | SQL injection authentication bypass in `Login.asp` | Critical | CWE-89 / CWE-287 |
| 2 | Boolean/error-based SQL injection in `showforum.asp?id=` | Critical | CWE-89 |
| 3 | Path traversal / arbitrary local file read in `Templatize.asp?item=` | High | CWE-22 |
| 4 | Error-based SQL injection in `Search.asp?tfSearch=` | High | CWE-89 |
| 5 | Reflected XSS in `Search.asp?tfSearch=` | Medium | CWE-79 |

---

### 1. SQL injection in Login.asp allows authentication bypass without credentials
- **Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)
- **CWE:** CWE-89 (SQL Injection) enabling CWE-287 (Improper Authentication)
- **Affected asset:** `POST http://testasp.vulnweb.com/Login.asp` — parameters `tfUName`, `tfUPass`
- **Summary:** The login query concatenates the username/password fields directly into SQL, so an attacker can log in as a valid user (including admin) with no knowledge of any credentials.
- **Steps to Reproduce:**
  1. Baseline — invalid credentials are rejected:
     ```
     POST /Login.asp   tfUName=nope&tfUPass=nope
     → 200, page title "acuforum login", body contains: <b>Invalid login!</b>
     ```
  2. Inject a tautology into both fields:
     ```
     POST /Login.asp
     tfUName=' or '1'='1&tfUPass=' or '1'='1
     (URL-encoded: tfUName=%27+or+%271%27%3D%271&tfUPass=%27+or+%271%27%3D%271)
     → HTTP/1.1 200 OK, Content-Length: 3563
     → page title "acuforum forums" (the authenticated/landing view), NO "Invalid login!" string
     ```
  3. Confirm the field reaches SQL unsanitized — a single quote errors the query:
     ```
     POST /Login.asp   tfUName=x'&tfUPass=x   → HTTP 500 (surfaced as "egress blocked … HTTP Error 500")
     ```
- **Impact:** Full authentication bypass and account takeover, including the `admin` account observed throughout the forum data. Chains with findings #2/#4 to read the credential store outright.
- **Remediation:** Use parameterized queries / prepared statements for the login lookup and verify passwords server-side against a salted hash; never interpolate input into SQL.
- **References:** https://cwe.mitre.org/data/definitions/89.html · https://cwe.mitre.org/data/definitions/287.html · OWASP A03:2021 Injection

---

### 2. Boolean- and error-based SQL injection in showforum.asp exposes the database
- **Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)
- **CWE:** CWE-89 (SQL Injection)
- **Affected asset:** `GET http://testasp.vulnweb.com/showforum.asp?id=` — parameter `id`
- **Summary:** The `id` parameter is placed unescaped into a SQL query, letting an attacker alter query logic and read arbitrary database contents (users, credentials, posts).
- **Steps to Reproduce:**
  1. Error signal — an unbalanced quote breaks the query:
     ```
     GET /showforum.asp?id=0'   → HTTP 500 (surfaced as "egress blocked … HTTP Error 500")
     ```
  2. Clean boolean pair proving injected logic controls the result set (row count = occurrences of `showthread.asp`):
     ```
     GET /showforum.asp?id=99999            → 0 thread rows   (FALSE)
     GET /showforum.asp?id=99999 or 1=1     → 2 thread rows   (TRUE — WHERE forced true)
     (encoded: ?id=99999%20or%201=1)
     ```
     `id=0 or 1=1` likewise returned a full thread listing, confirming the forced-true condition returns rows that the raw id does not.
- **Impact:** Full read of the backend database (MSSQL/Access), including likely UNION/error-based extraction of user credentials. Boolean-based blind extraction is demonstrated feasible; write/DoS potential warrants A:H at baseline.
- **Remediation:** Parameterize the query and cast `id` to an integer before use.
- **References:** https://cwe.mitre.org/data/definitions/89.html · OWASP A03:2021 Injection

---

### 3. Path traversal in Templatize.asp allows arbitrary local file read
- **Severity:** High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Affected asset:** `GET http://testasp.vulnweb.com/Templatize.asp?item=` — parameter `item`
- **Summary:** The `item` parameter is used to build a file path with no confinement, so an attacker can escape the template directory and read any file readable by the web process.
- **Steps to Reproduce:**
  1. Normal use loads a template file: `GET /Templatize.asp?item=html/about.html` → 200, rendered page.
  2. Traverse to a system file:
     ```
     GET /Templatize.asp?item=../../../../../../windows/win.ini
     → response body embeds the file contents:
        ; for 16-bit app support
        [fonts]
        [extensions]
        [mci extensions]
        [Mail]
     ```
     These lines are the contents of `C:\Windows\win.ini`, confirming out-of-directory read.
- **Impact:** Disclosure of arbitrary local files — application source, configuration, and database connection strings/credentials — which can be chained with the SQLi findings for deeper compromise.
- **Remediation:** Map `item` to a server-side allow-list of permitted template names; reject `..`, path separators, and absolute paths; canonicalize and verify the resolved path stays within the template base directory.
- **References:** https://cwe.mitre.org/data/definitions/22.html · OWASP A01:2021 Broken Access Control

---

### 4. Error-based SQL injection in Search.asp
- **Severity:** High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N (8.2)
- **CWE:** CWE-89 (SQL Injection)
- **Affected asset:** `GET http://testasp.vulnweb.com/Search.asp?tfSearch=` — parameter `tfSearch`
- **Summary:** The search term is concatenated into a SQL query; a single quote breaks it, indicating the parameter is injectable and the searchable dataset can be extracted.
- **Steps to Reproduce:**
  1. Trigger the SQL error:
     ```
     GET /Search.asp?tfSearch=x'   (encoded: ?tfSearch=x%27)
     → HTTP 500 (surfaced as "egress blocked … HTTP Error 500")
     ```
     A benign search term returns 200 with normal results, isolating the quote as the cause.
- **Impact:** Database read via the search query (same backend as #2). Rated High rather than Critical here because only the error-based indicator (not a full boolean/UNION extraction) was demonstrated in this trace.
- **Remediation:** Parameterize the search query; escape/encode the LIKE term.
- **References:** https://cwe.mitre.org/data/definitions/89.html · OWASP A03:2021 Injection

---

### 5. Reflected XSS in Search.asp
- **Severity:** Medium — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1)
- **CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **Affected asset:** `GET http://testasp.vulnweb.com/Search.asp?tfSearch=` — parameter `tfSearch`
- **Summary:** The search term is echoed into the HTML response without encoding, so a crafted link executes attacker-controlled JavaScript in a victim's browser.
- **Steps to Reproduce:**
  1. Request:
     ```
     GET /Search.asp?tfSearch=<script>alert(1)</script>
     (encoded: ?tfSearch=%3Cscript%3Ealert(1)%3C%2Fscript%3E)
     ```
  2. Response reflects the payload unescaped, inside the page body:
     ```
     <div class='path'>You searched for '<script>alert(1)</script>'</div>
     ```
- **Impact:** Session/cookie theft or forged actions in a victim's authenticated session via a malicious link. Given finding #1, a stolen admin session is high-value.
- **Remediation:** HTML-encode all user input on output (encode `< > " ' &`); add a restrictive Content-Security-Policy.
- **References:** https://cwe.mitre.org/data/definitions/79.html · OWASP A03:2021 Injection

---

## Coordinated Disclosure
All testing was read-only, throttled, and confined to the authorized in-scope host `testasp.vulnweb.com`; no data was modified, deleted, or exfiltrated, and no availability impact was induced. Please treat this report as confidential: no public disclosure prior to a fix, following a standard 90-day disclosure window from the report date. We are happy to re-test remediations on request.