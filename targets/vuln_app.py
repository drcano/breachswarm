"""Deliberately-vulnerable demo app for the web specialist to exploit.

Self-hosted target (authorised by construction) that proves the agent works
against a LIVE service, not just static CTF files. Two planted bugs:

  1. Server-Side Template Injection (SSTI) at /greet?name=  — user input is
     concatenated into a Jinja2 template. The flag lives in app.config and is
     reachable via `{{ config['FLAG'] }}` (or full SSTI RCE).
  2. A robots.txt hint pointing at /greet.

Run: pip install flask && python vuln_app.py  (or via targets/Dockerfile)
"""
from flask import Flask, request, render_template_string

app = Flask(__name__)
app.config["FLAG"] = "flag{ss7i_l1v3_t4rg3t_pwn3d}"


@app.route("/")
def index():
    return ("<h1>StonksBot 3000</h1><p>AI-powered trading. Nothing to see here.</p>"
            "<!-- TODO: remove the debug greeter before launch -->")


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /greet\n", 200, {"Content-Type": "text/plain"}


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    # VULN: raw user input rendered as a template -> SSTI
    return render_template_string("<h1>Hello " + name + "!</h1>")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
