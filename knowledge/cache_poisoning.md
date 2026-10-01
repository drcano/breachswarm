## Web Cache Poisoning & Cache Deception
A shared cache (CDN/reverse proxy) sits in front of the app. Two abuses: POISON it so every user gets your
payload, or DECEIVE it into caching another user's private response.

First, find cached responses: `curl -sI URL | grep -iE 'cache-control|x-cache|age|cf-cache-status'`.
`X-Cache: HIT`, `Age: >0`, `CF-Cache-Status: HIT` = cacheable. Note what the cache KEY is (usually
method+host+path+query) and what it is NOT.

Cache poisoning (unkeyed input reflected + cached):
- Find an unkeyed header that the response reflects but the cache ignores. Test one at a time:
  `X-Forwarded-Host: evil.com`, `X-Forwarded-Scheme`, `X-Host`, `X-Forwarded-Server`, `X-Original-URL`.
  Burp **Param Miner** → "Guess headers" automates this.
- If `evil.com` lands in the body (e.g. an absolute script/resource URL, a redirect, an og: tag) AND the
  response is cached, every subsequent visitor to that cache key gets your value → stored XSS / redirect /
  resource hijack for all users. Impact multiplier: poison a JS/CSS URL → mass XSS.
- Fat GET / param cloaking: unkeyed query param, duplicate params the cache and origin key differently.
- To exploit: send the poisoned request repeatedly until it wins the cache slot for the real URL; verify
  from a clean client (no attacker headers) that the poison persists.

Cache deception (cache stores a victim's authenticated response):
- Request a private page with a static-looking suffix the cache caches by extension but the origin ignores:
  `/account/settings` → `/account/settings/nonexistent.css` (or `.js`,`.jpg`). Cache sees `.css` → caches;
  origin path-matches `/account/settings` → returns the victim's private data.
- Delimiter variants when the naive suffix fails: `/account/settings;.css`, `/account/settings%2f..%2fx.css`,
  `/account/settings%00.css`, `/account/settings/.css`, `/account/settings#.css`, `/account/settings?x=.css`.
- Path-normalization differential: cache sees `/static/..%2fapi/private` as static and caches; origin
  resolves to `/api/private`. Same idea, cache vs origin disagree on the path.
- Exploit: lure the victim to the crafted URL (their cookies populate the response), then you fetch the
  SAME URL with no cookies and read their cached PII/token. Detection: `grep -i 'cache-control\|x-cache'` —
  no `Cache-Control: private` + `x-cache: HIT` on an authed path = deception-cacheable.

Report the exact cache key, the unkeyed input (poisoning) or the extension/delimiter (deception), and prove
a second client receives the poisoned/private response. Chains: poisoned redirect → OAuth code theft
([[auth_reset_oauth]]); reflected header → XSS. See [[request_smuggling]] (desync can also poison caches).
