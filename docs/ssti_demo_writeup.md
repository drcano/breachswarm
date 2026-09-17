# StonksBot 3000 — SSTI Writeup

## Challenge

- **Name:** `live_ssti_demo`
- **Target:** `http://172.17.0.2:5000/` (live Flask/Werkzeug service, authorized to test)
- **Goal:** Find the hidden flag on the running service.
- **Result:** `flag{ss7i_l1v3_t4rg3t_pwn3d}`

The landing page is a stub for "StonksBot 3000" with a telling HTML comment:

```html
<h1>StonksBot 3000</h1><p>AI-powered trading. Nothing to see here.</p>
<!-- TODO: remove the debug greeter before launch -->
```

## Approach

No challenge files were provided locally — this is a live-target challenge, so all recon happens over HTTP. The homepage comment points at a "debug greeter," so the plan was: find the greeter endpoint, test it for injection, then pull the flag.

## Steps

**1. Local recon — nothing here.** `ls`/`file`/`strings` on the working directory turned up an empty folder. This confirmed the challenge is purely against the remote service, not static files.

**2. Fingerprint the service.** `curl -is` on `/` returned `Server: Werkzeug/3.1.8 Python/3.12.14` — a Flask app — plus the "debug greeter" comment. Flask + a hinted greeter strongly suggests Jinja2 SSTI.

**3. Find the greeter endpoint.** Brute-forced likely names: `greet`, `greeter`, `hello`, `debug`, `greeting`, `welcome`. Only `/greet` existed:

```
/greet → <h1>Hello guest!</h1>
```

The others 404'd. (Note: the app's `robots.txt` also disallowed `/greet` as an intended hint, though the name was guessed directly here.)

**4. Confirm SSTI.** Compared a plain value against a template-injection probe:

```
/greet?name=dante         → <h1>Hello dante!</h1>
/greet?name={{7*7}}       → <h1>Hello 49!</h1>
```

`{{7*7}}` evaluating to `49` confirms user input is rendered as a Jinja2 template — classic SSTI from `render_template_string("<h1>Hello " + name + "!</h1>")`.

**5. Escalate to RCE and hunt the flag.** Used the `cycler.__init__.__globals__.os` gadget to get command execution:

- First payload (`grep -rIl flag / ; env | grep -i flag`) returned only unrelated system paths and no flag env var — a **dead end**, but it confirmed full RCE worked.
- Second payload (`cat /flag*; ls -la /; cat /app/*.py`) had no `/flag*` file either, but dumping `/app/*.py` leaked the app source.

**6. Read the flag from source.** The leaked `vuln_app.py` revealed the flag was never on disk as a file — it lives in `app.config`:

```python
app.config["FLAG"] = "flag{ss7i_l1v3_t4rg3t_pwn3d}"
```

The source even documented the intended shortest path: `{{ config['FLAG'] }}` — no RCE required. The file-grep/env approach missed it because the flag was in application config, not the filesystem or environment.

## Flag

```
flag{ss7i_l1v3_t4rg3t_pwn3d}
```

## Takeaways

- **The homepage comment was the whole map:** "debug greeter" → find `/greet` → SSTI. Read the free hints first.
- **`{{7*7}}` before RCE gadgets.** One cheap probe confirmed the vuln class before any heavy payloads.
- **Know where Flask hides secrets.** Grepping the filesystem and env for `flag` was a wasted round — for a Flask app the fastest read is `{{ config }}` / `{{ config['FLAG'] }}`, since secrets commonly live in `app.config`. RCE worked, but the intended path was a single template expression.
- **Source disclosure closes the case.** Dumping `/app/*.py` turned guesswork into certainty about where the flag lived and why the earlier searches came up empty.