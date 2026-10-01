# Go-Live Checklist — Running Against a Real Bug-Bounty Program

The system will **refuse** to run against a target unless authorization is
explicitly declared. This is the pre-flight before any real external engagement.
Nothing here is optional — it is the difference between security research and
unauthorized access.

## 1. Confirm the program permits automated testing

- [ ] The program's policy page **explicitly allows automated/agent/scanner
      testing.** Many programs forbid it — if it's not clearly permitted, stop.
- [ ] Note the exact policy URL and the sentence that grants it.

See [`docs/targets.md`](targets.md) for the qualify-before-run checklist and the two
programs research surfaced as automation-permitting (Shopify, Google VRP) — re-verify each
program's live policy every time; silence ≠ permission.

## 2. Declare scope in a file

Copy `scope.example.json` → `scope.mine.json` and fill it in:

```json
{
  "program": "<real program name>",
  "authorized": true,
  "in_scope": ["*.target.com", "203.0.113.0/24"],
  "out_of_scope": ["admin.target.com", "*.internal.target.com"],
  "rate_limit_rps": 1.0,
  "allow_metadata_hosts": false
}
```

- [ ] `authorized` is `true` **only** because step 1 is satisfied.
- [ ] `in_scope` lists **only** assets the program names as in-scope.
- [ ] `out_of_scope` mirrors the program's exclusions.
- [ ] `rate_limit_rps` respects the program's stated limits.

The always-deny list (cloud metadata `169.254.169.254`, `.gov`, `.mil`,
localhost) is enforced regardless of what the scope file says.

## 3. Run with network-layer enforcement

```bash
python bounty.py --scope scope.mine.json --target https://<in-scope-asset> --enforce
```

`--enforce` puts the agent on an internal-only Docker network whose **only**
route out is an allowlisting proxy that checks every request against the scope.
An out-of-scope request fails at the network layer — the agent cannot reach it
even if it tries.

## 4. Verify before you trust

- [ ] `scope.py` self-check passes: `python scope.py`
- [ ] Dry-run the enforcement against your own instance first (see below).
- [ ] Review the `audit.jsonl` after the run — every action is logged.

## 5. Report responsibly

- [ ] Submit the generated report (`bounty_runs/<ts>/findings.md`) through the
      program's official channel only.
- [ ] Do not retest or pivot beyond scope based on what you find.

---

## Recommended first real target: self-hosted Juice Shop dry-run

Before pointing at anything external, prove the `--enforce` path end-to-end
against your own instance:

```bash
docker run -d --rm -p 3000:3000 bkimminich/juice-shop
# scope.juice.json already authorizes the local instance
python bounty.py --scope scope.juice.json --target http://<instance-ip>:3000 --enforce
```

If that produces a clean report through the enforced proxy, the pipeline is
validated and the only remaining variable for a real run is the program's
authorization (step 1).
