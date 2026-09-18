## Subdomain Takeover & Cache Poisoning
Subdomain takeover:
- Find dangling DNS: `subfinder`/`amass` -> resolve each -> a CNAME pointing to an UNCLAIMED third-party (S3 `NoSuchBucket`, GitHub Pages 404 "There isn't a GitHub Pages site here", Heroku "no such app", Azure, Zendesk, Shopify, Fastly, Netlify, Surge, unbounced).
- Fingerprint the error body; claim the resource (register the bucket/app/repo with the referenced name) -> you serve content on the victim's trusted subdomain.
- Escalate: host XSS/phishing on a trusted origin, steal cookies scoped to `*.domain`, bypass CORS/CSP allowlists, OAuth redirect allowlist abuse, capture session cookies. Tool: `nuclei -t takeovers`, `subjack`.

## Web Cache Poisoning & Deception
Poisoning: find an UNKEYED input that changes the response (headers `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Host`, or an unkeyed query param). Inject a payload (XSS/redirect) via the unkeyed input; if it's cached (check `X-Cache: hit`, `Age`, `CF-Cache-Status`), every subsequent user is served your payload.
- Cache-key probing: Param Miner; vary one header, watch for reflection + cache hit.
Deception: trick the cache into storing a victim's PRIVATE page — `/account.css`, `/account/../account`, `/account;.js`, path/extension confusion so the CDN caches an authenticated response, then read it unauthenticated.
Escalate: mass stored-XSS, credential/PII theft, cache-key auth bypass.
