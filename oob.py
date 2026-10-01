"""Out-of-band (OOB) interaction server — confirm BLIND vulnerabilities.

Many high-severity bugs are blind: the server DOES the thing (SSRF fetch, XXE, DNS lookup, webhook
send) but nothing comes back in the HTTP response, so an in-band tester sees only a timeout or a
generic error and cannot prove it. The proof is an out-of-band callback: inject a unique URL you
control; if your server logs a hit on that token, the target reached out — blind vuln confirmed.

Topology: run this on a host the TARGET can reach. Locally that means exposing it with a tunnel
(cloudflared / ngrok) and setting OOB_PUBLIC_URL to the tunnel URL. Mint a token, inject
`<public>/<token>` into the sink, then poll for interactions on that token. The bounty runner's
`oob` tool talks to this server from the runner process (host-side), so it is NOT subject to the
sandbox egress proxy.

Run: ./.venv/bin/python oob.py --port 9000 --tunnel   # one command: server + public tunnel +
prints `export OOB_PUBLIC_URL=...` (needs cloudflared or ngrok on PATH; cloudflared quick tunnels
need no account). `provision()` does the same in-process for the runner.
ponytail: HTTP-only, in-memory + jsonl. DNS-only OOB (DNS-rebind, blind-DNS exfil) and TLS need a
DNS server — reach for interactsh if that class becomes worth it.
NOTE (measured 2026-09-22): cloudflared quick tunnels connect fine (registered, pre-checks pass) but
the `<random>.trycloudflare.com` DNS record can take 30-90s to propagate and negative-DNS caching
makes the first callbacks flaky — for a reliable engagement use a cloudflared NAMED tunnel (stable
hostname) or interactsh, not the account-less quick tunnel. provision() is correct either way.
"""
from __future__ import annotations

import argparse
import json
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_STORE: dict[str, list[dict]] = {}          # token -> [interaction, ...]
_LOCK = threading.Lock()
_LOG = "oob_log.jsonl"


def mint_token() -> str:
    return uuid.uuid4().hex[:16]


def mint_url(public_base: str) -> tuple[str, str]:
    """(token, callback_url). Inject callback_url into the suspected sink."""
    t = mint_token()
    return t, public_base.rstrip("/") + "/" + t


def token_of(path: str) -> str:
    """First path segment is the token (…/<token>/anything or …/<token>)."""
    return path.lstrip("/").split("/", 1)[0].split("?", 1)[0]


def record(method: str, path: str, headers: dict, remote: str,
           store: dict = _STORE, log: str | None = _LOG) -> str:
    """Record one inbound interaction under its token; returns the token."""
    tok = token_of(path)
    if not tok or tok.startswith("_"):
        return ""
    hit = {"ts": round(time.time(), 2), "method": method, "path": path, "remote": remote,
           "ua": headers.get("User-Agent", ""), "host": headers.get("Host", "")}
    with _LOCK:
        store.setdefault(tok, []).append(hit)
    if log:
        try:
            with open(log, "a") as f:
                f.write(json.dumps({"token": tok, **hit}) + "\n")
        except Exception:
            pass
    return tok


def hits(token: str, store: dict = _STORE) -> list[dict]:
    with _LOCK:
        return list(store.get(token, []))


def poll(local_base: str, token: str, timeout: float = 5.0) -> list[dict]:
    """Client side (runs in the bounty runner): ask a running OOB server for a token's hits."""
    url = local_base.rstrip("/") + "/_oob/" + token
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read() or b"[]")
    except Exception:
        return []


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):   # quiet; interactions are the log
        pass

    def _reply(self, code: int, body: bytes, ctype: str = "text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        # control API: /_oob/<token> -> the recorded interactions for that token
        if self.path.startswith("/_oob/"):
            tok = self.path[len("/_oob/"):].split("?", 1)[0]
            return self._reply(200, json.dumps(hits(tok)).encode(), "application/json")
        # everything else is a target callback — log it, return a tiny 200 so the fetch "succeeds"
        remote = self.client_address[0] if self.client_address else ""
        record(self.command, self.path, {k: v for k, v in self.headers.items()}, remote)
        self._reply(200, b"ok")

    do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = do_OPTIONS = _handle


def _parse_tunnel_url(line: str) -> str:
    """Extract the public URL a tunnel binary prints (cloudflared quick tunnel / ngrok)."""
    import re
    m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", line or "")
    if m:
        return m.group(0)
    m = re.search(r"https://[a-z0-9-]+\.ngrok(?:-free)?\.(?:app|io)", line or "")
    return m.group(0) if m else ""


def _tunnel_cmd(port: int):
    """(argv, tool-name) for an available zero-config tunnel, or (None, None). cloudflared quick
    tunnels need NO account; ngrok needs a configured authtoken."""
    import shutil
    if shutil.which("cloudflared"):
        return ["cloudflared", "tunnel", "--url", f"http://localhost:{port}", "--no-autoupdate"], "cloudflared"
    if shutil.which("ngrok"):
        return ["ngrok", "http", str(port), "--log=stdout"], "ngrok"
    return None, None


def provision(port: int = 9000, timeout: float = 30.0) -> dict:
    """Stand up the collaborator in ONE call: start the OOB server (background thread) + a public
    tunnel, and return {public_url, local_base, server, tunnel, tool}. Raises with setup guidance if
    no tunnel binary is available. This is the piece that was missing — the server was built, but
    nothing exposed it / set OOB_PUBLIC_URL."""
    import subprocess
    try:
        server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    except OSError:                                 # requested port busy -> take any free port
        server = ThreadingHTTPServer(("0.0.0.0", 0), _Handler)
        port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    cmd, tool = _tunnel_cmd(port)
    if not cmd:
        server.shutdown()
        raise RuntimeError(
            "[oob] no tunnel binary found. Install one (macOS: `brew install cloudflared`; "
            "or download cloudflared) — a cloudflared quick tunnel needs no account. Alternatively "
            "set OOB_PUBLIC_URL yourself to an existing collaborator (interactsh/Burp).")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line and proc.poll() is not None:
            break
        url = _parse_tunnel_url(line)
        if url:
            return {"public_url": url, "local_base": f"http://localhost:{port}",
                    "server": server, "tunnel": proc, "tool": tool}
    try:
        proc.terminate()
    except Exception:
        pass
    server.shutdown()
    raise RuntimeError(f"[oob] {tool} did not report a public URL within {timeout:.0f}s")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--tunnel", action="store_true",
                    help="also start a public tunnel (cloudflared/ngrok) and print OOB_PUBLIC_URL")
    args = ap.parse_args()
    if args.tunnel:
        prov = provision(args.port)
        print(f"export OOB_PUBLIC_URL={prov['public_url']}    # via {prov['tool']}")
        print(f"[oob] collaborator live: {prov['public_url']} (poll base {prov['local_base']}); "
              f"Ctrl-C to stop")
        try:
            prov["tunnel"].wait()
        except KeyboardInterrupt:
            prov["tunnel"].terminate(); prov["server"].shutdown()
        return
    print(f"[oob] logging interactions on {args.host}:{args.port} — expose via a tunnel (or run with "
          f"--tunnel) and set OOB_PUBLIC_URL; poll GET /_oob/<token>")
    ThreadingHTTPServer((args.host, args.port), _Handler).serve_forever()


def demo() -> None:
    s: dict = {}
    tok, url = mint_url("https://oob.example.com")
    assert url.endswith("/" + tok) and len(tok) == 16
    # a target callback to /<token>/latest/meta-data records under the token
    assert record("GET", f"/{tok}/latest/meta-data", {"User-Agent": "Go-http", "Host": "x"},
                  "10.0.0.9", store=s, log=None) == tok
    assert record("POST", f"/{tok}", {}, "10.0.0.9", store=s, log=None) == tok
    assert len(hits(tok, s)) == 2 and hits(tok, s)[0]["method"] == "GET"
    assert hits("never-seen", s) == []                     # no callback -> not confirmed
    assert record("GET", "/_oob/x", {}, "1.2.3.4", store=s, log=None) == ""   # control path ignored
    assert token_of("/abcd1234/a/b?q=1") == "abcd1234"
    # tunnel URL parsing (cloudflared quick-tunnel box + ngrok stdout log shapes)
    assert _parse_tunnel_url("INF |  https://swift-brave-cat-42.trycloudflare.com  |") == \
        "https://swift-brave-cat-42.trycloudflare.com"
    assert _parse_tunnel_url('msg="started tunnel" url=https://ab12cd.ngrok-free.app') == \
        "https://ab12cd.ngrok-free.app"
    assert _parse_tunnel_url("cloudflared: starting metrics server") == ""
    # provision must fail with clear setup guidance when no tunnel binary is installed
    import shutil
    if not (shutil.which("cloudflared") or shutil.which("ngrok")):
        try:
            provision(port=9137, timeout=1); assert False, "should have raised"
        except RuntimeError as e:
            assert "no tunnel binary" in str(e), str(e)
    print("oob.py ok —", url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] in ("demo", "-t"):
        demo()
    else:
        main()
