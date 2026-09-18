## Secrets & Sensitive Exposure (recon-first)
The cheapest critical findings are things left exposed. Check every target for these
BEFORE heavy exploitation — one leaked key can shortcut the whole chain.
Exposed VCS / config / backups:
- `/.git/` (grab `.git/config`, `.git/HEAD`, then `git-dumper`/download objects -> full
  source + history secrets), `/.svn/`, `/.hg/`.
- `/.env`, `/config.php.bak`, `/settings.py`, `/wp-config.php`, `/appsettings.json`,
  `/docker-compose.yml`, `/.aws/credentials`, editor backups `file.php~`, `.swp`,
  `/backup.zip`, `/db.sql`, `/dump.sql`.
Client-side leakage:
- JS source maps (`.js.map`) reconstruct original source; read bundled JS for API routes,
  hardcoded API keys, tokens, internal hostnames, feature flags, secret endpoints.
- HTML comments, hidden fields, `window.__CONFIG__`, inline JS with keys.
API/infra disclosure:
- `swagger.json`/`openapi.json`/`/api-docs`, GraphQL introspection, `/actuator/*`
  (Spring: `/actuator/env`, `/heapdump`, `/actuator/health`), `/metrics`, `/debug`,
  `/phpinfo.php`, `/server-status`, verbose stack traces (leak paths/versions/queries).
- Directory listing enabled; `robots.txt`/`sitemap.xml` reveal hidden paths.
Key hunting: recovered keys -> test them (cloud keys `aws sts get-caller-identity`,
Google/Stripe/Slack/GitHub tokens, JWT signing secrets, DB creds). Search dumps/JS with
regex for `AKIA[0-9A-Z]{16}`, `AIza...`, `xox[baprs]-`, `ghp_`, `sk_live_`, `-----BEGIN`.
Escalate: source -> more bugs; key -> direct access; backup/db -> full data. Chain via
[[chains]].
