## NoSQL Injection (Mongo/etc.)
Where: JSON login/search/filter APIs backed by MongoDB/CouchDB/etc. Params that become query operators.
Auth bypass (operator injection): send JSON `{"user":"admin","pass":{"$ne":null}}` or `{"$gt":""}` -> matches any password. In URL/form: `user[$ne]=x&pass[$ne]=x` (PHP/Express array parsing).
Operators: `$ne`, `$gt`, `$gte`, `$regex` (`{"pass":{"$regex":"^a"}}` -> boolean-blind char-by-char extraction of secrets), `$in`, `$exists`, `$where` (JS eval: `{"$where":"this.pass.length>5"}` or `{"$where":"sleep(5000)"}` time-blind).
Extract data: `$regex` prefix-match to leak passwords/tokens one char at a time (`^a`, `^ab`, ...); `$where` JS for arbitrary boolean/time oracles.
JS injection ($where / mapReduce): full JS context -> `return true`, timing, sometimes RCE on old/misconfigured servers.
Bypass string filters: nested operators, unicode, type juggling; set `Content-Type: application/json` when the app expects form (many parse both).
Escalate: auth bypass -> admin; blind regex -> full credential dump; `$where` -> DoS/RCE. Tool: `nosqlmap`, but a manual `$ne`/`$regex` PoC is cleaner.
