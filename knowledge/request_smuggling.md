## HTTP Request Smuggling (Desync)
Where: front-end proxy/CDN/LB + back-end origin that disagree on request boundaries. Look for stacked servers (`Via`, `X-Cache`, differing `Server`).
Variants: CL.TE (front uses Content-Length, back uses Transfer-Encoding), TE.CL (reverse), TE.TE (one is tricked into ignoring TE via obfuscation `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`, ` chunked`, `chunked\r\n`, tab).
Detect safely: timing test — a CL.TE probe that leaves the back-end waiting for bytes causes a measurable delay on the NEXT request. Use Burp's smuggler / `smuggler.py`; prefer detection over live poisoning.
Classic CL.TE body:
```
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
HTTP/2 downgrade: h2.TE/h2.CL desync via smuggled `\r\n` in header values, malformed `:path`/`content-length`.
Escalate: prepend to a victim's request to steal it (capture creds/session), bypass front-end auth/WAF (smuggle a request the front never authorizes), cache poisoning, cred harvest. High impact; test carefully on authorized targets only — it affects other users.
