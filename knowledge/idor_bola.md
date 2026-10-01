## IDOR / BOLA (broken object-level authorization) — highest-frequency high-sev
Where: every object id in a path/param/body — `/api/users/{id}`, `?order_id=`, `?file=`, GraphQL node global ids, `/api/BasketItems/{id}`.
Technique: with your own low-priv session, swap the id for another user's / another tenant's and see if you get their data. Try sequential ids, UUID enumeration via leaks, and predictable ids.
Method override: if GET is checked but the object is mutable, try `PUT/PATCH/DELETE` on the same id; try `X-HTTP-Method-Override: PUT`.
Missing authZ: hit "admin/protected" routes with a low-priv or NO token — many check authentication but not authorization.
Escalate: read/modify others' PII, orders, baskets, messages; account takeover if you can change another user's email/password; cross-tenant = critical.
Batch/GraphQL: alias-batch many ids in one request to enumerate fast (mind rate limits/stealth).
