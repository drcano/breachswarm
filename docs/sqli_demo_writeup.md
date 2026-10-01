## Challenge

**live_sqli_demo** — The StonksBot login service at `http://172.17.0.2:5000/` exposes a `/login` endpoint taking `user` and `pass` query params. Goal: recover a hidden flag from the database. Stack revealed by headers: Werkzeug/Flask + Python 3.12, backed by SQLite.

## Approach

Confirm SQL injection on `user`, then figure out how the app leaks data. The response is a fixed `Welcome admin!` / `Invalid credentials` string, so UNION output can't be read directly — it's a **boolean-blind** oracle. Extract the schema and flag one bit at a time via binary search on `unicode(substr(...))`.

## Steps

1. **Recon.** `GET /` returns a plain login form. `GET /login?user=admin&pass=admin` → `Invalid credentials`. Baseline established.

2. **Injection confirmed.** Three payloads all returned `Welcome admin!`:
   - `admin'-- -`
   - `admin' OR '1'='1`
   - `x' OR 1=1-- -`
   
   The `user` param is injected straight into the query and the app authenticates on any truthy result.

3. **Column count.** `UNION SELECT NULL,...` across 1–5 columns: only **3 columns** succeeded (SQLite error message leaked for the rest — a bonus error-based channel). 

4. **Dead end — UNION extraction.** Tried `UNION SELECT 'A','B','C'` and variants to find a reflected column. Every one returned the hardcoded `Welcome admin!` regardless of injected values. **The success message is a constant, not echoed row data** — UNION gets you nothing to read.

5. **Dead end — sqlmap.** Ran `sqlmap --technique=BU --string="Welcome" --dump`. It confirmed 3 columns and heuristic injectability but bailed: the `--string` match wasn't in the raw response as sqlmap probed it, NULL-based UNION wasn't exploitable, and it logged 19x HTTP 500s. Automated tooling gave up; the target needed a hand-built oracle.

6. **Oracle verification.** Confirmed a clean true/false split:
   - `admin' AND 1=1-- -` → `Welcome admin!` (true)
   - `admin' AND 1=2-- -` → `Invalid credentials` (false)
   
   Presence of `"Welcome"` in the response = TRUE. Solid boolean oracle.

7. **Blind extractor.** Wrote a short Python script: for each character position, check `length()` to detect end-of-string, then binary-search the byte with `unicode(substr((expr),i,1)) > mid`. Dumped the schema from `sqlite_master`:
   ```
   CREATE TABLE users(id INTEGER, user TEXT, pass TEXT)~~CREATE TABLE secret(flag TEXT)
   ```

8. **Flag extraction.** Reused the extractor against `SELECT flag FROM secret`.

## Flag

```
flag{sql1_dump3d_by_the_agent}
```

## Takeaways

- **A constant success message kills UNION.** When the app returns the same string no matter what row you inject, in-band extraction is dead — recognize it early and pivot to blind rather than fuzzing UNION column positions.
- **sqlmap isn't magic.** Here it flagged the injection but couldn't exploit it (constant response string + NULL-unfriendly UNION). A ~15-line hand-rolled boolean extractor beat it.
- **The error messages were a second free channel.** SQLite errors leaked verbatim (column-count mismatch), which alone confirmed the 3-column SQLite backend — worth remembering as an error-based fallback.
- **Binary search over `unicode(substr())` is the reliable blind primitive** — ~7 requests per character, works on any boolean oracle.