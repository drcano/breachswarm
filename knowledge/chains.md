## Exploit Chains — combining primitives into critical impact
Most high-severity findings are CHAINS: a low/medium bug becomes critical when its OUTPUT feeds the next bug's INPUT. Always ask: "what did this primitive just give me, and which endpoint does that unlock?" Carry every artifact forward — a leaked token/key/cred/internal-URL/source-file is the input to the next stage, and it usually unlocks an endpoint you have ALREADY seen.
Canonical chains (recognize the shape):
- SQLi/leak -> credentials/API-token -> authenticated endpoint -> privilege escalation.
- Weak auth -> mass-assignment (`role`/`account_type` nested) -> admin -> admin-only feature.
- SSRF -> cloud metadata (`169.254.169.254`, decimal/hex if filtered) -> temp cloud creds -> cloud API / RCE. (top-paid)
- File read (LFI/path traversal) -> source/config -> secret (JWT key, DB creds, API key) -> auth forge / DB access.
- Open redirect / XSS on callback -> OAuth `code`/token theft -> account takeover.
- SSTI / deserialization / file upload / cmd injection -> RCE -> read flag / lateral movement.
- IDOR -> other users' data -> admin object -> full compromise.
- XXE -> file read + SSRF -> internal service -> escalation.
Method: (1) enumerate the WHOLE surface first (recon) so you know what a new credential could open. (2) When a stage yields an artifact, STOP and re-target: which known endpoint now accepts it? (3) Track state explicitly (tokens, keys, URLs, roles discovered). (4) Egress/WAF filters block the literal, not the technique — re-encode (alt IP, `/**/`, case, double-encode) and retry the SAME idea, don't abandon it. (5) A decoy/tarpit endpoint that only ever errors is not the path — pivot.
Gate recognition: if an endpoint says "locked"/"requires X"/"admin only", X is your next objective, not a dead end.
