## Mass assignment / auto-binding privilege escalation
Where: JSON/form endpoints that bind request fields to an object (user profile, order, settings).
Technique: add fields the UI never sends — `"role":"admin"`, `"isAdmin":true`, `"is_staff":true`, `"verified":true`, `"balance":99999`, `"account_type":"admin"`, `"group":"administrators"`.
Defense bypass: if top-level `role` is stripped, try NESTED `"profile":{"account_type":"admin"}` or `"user[role]":"admin"` or dot-notation `"role.name":"admin"`; try on registration, profile-update (PATCH), and password-reset.
Related: excessive data exposure — the GET may return more fields than the UI shows (tokens, hashes, internal flags) — read every response fully.
Confirm: re-fetch the object and check the privileged field stuck; then use the elevated session.
