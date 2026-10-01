## WAF / filter evasion (use surgically — evasion trials are noisy)
Keyword filters: inline comments `un/**/ion` is NOT valid, but `union/**/select` IS (comment separates two full tokens). Case `SeLeCt`. Nested `SELSELECTECT` if the WAF strips once.
Encoding: URL `%53`, double-URL `%2553`, unicode/overlong, HTML entities, `S`. Try where the WAF decodes fewer times than the app.
Whitespace: `%09` tab, `%0a` newline, `%0c`, `/**/`, `+`, `%a0`.
IP (SSRF): decimal/hex/octal (see ssrf).
Path (traversal): `..%2f`, `..%252f`, `....//`, `%2e%2e/`, unicode `%c0%ae`.
XSS filter: event handlers `onerror`, `onpointerover`, SVG vectors, `<img src=x onerror=...>`, JSFuck, no-parentheses.
Rate/lockout: rotate casing/params to look like distinct requests only if the RoE allows; otherwise slow down.
Principle: one hypothesis-driven evasion at a time, not a spray — every blocked request is noise a defender logs.
