"""Allowlisting egress proxy — enforces scope at the network layer.

The agent sandbox is given HTTP(S)_PROXY pointing here and (in the hardened
topology) has no other route out, so EVERY outbound request is checked against the
scope allowlist before it leaves. Out-of-scope hosts get 403; in-scope traffic is
rate-limited and forwarded. Handles both plain HTTP and HTTPS (CONNECT tunnels).

Run: ./.venv/bin/python egress_proxy.py --scope scope.json --port 8888
"""
from __future__ import annotations

import argparse
import select
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from scope import Scope

SCOPE: Scope
_last = [0.0]
_lock = threading.Lock()


def _rate_gate():
    with _lock:
        gap = 1.0 / max(SCOPE.rate_limit_rps, 0.01)
        wait = _last[0] + gap - time.time()
        if wait > 0:
            time.sleep(wait)
        _last[0] = time.time()


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet; the audit trail is elsewhere
        pass

    def _deny(self, host, reason):
        body = f"egress blocked: {host} — {reason}".encode()
        self.send_response(403); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def do_CONNECT(self):  # HTTPS
        host = self.path.split(":")[0]
        ok, reason = SCOPE.allows("https://" + host)
        if not ok:
            return self._deny(host, reason)
        _rate_gate()
        port = int(self.path.split(":")[1]) if ":" in self.path else 443
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except Exception as e:
            return self._deny(host, f"connect failed: {e}")
        self.send_response(200, "Connection Established"); self.end_headers()
        self._tunnel(self.connection, upstream)

    def _http(self):
        host = urlparse(self.path).hostname or ""
        ok, reason = SCOPE.allows(self.path)
        if not ok:
            return self._deny(host, reason)
        _rate_gate()
        try:
            import urllib.request, urllib.error
            req = urllib.request.Request(self.path, method=self.command,
                                         headers={k: v for k, v in self.headers.items()})
            length = int(self.headers.get("Content-Length", 0))
            if length:
                req.data = self.rfile.read(length)
            try:
                r = urllib.request.urlopen(req, timeout=15)
            except urllib.error.HTTPError as he:
                r = he  # a non-2xx IS a real response (500 = SQL error signal!) —
                        # pass it through, don't mistake it for a scope block
            with r:
                body = r.read()
                self.send_response(r.status)
                self.send_header("Content-Length", str(len(body))); self.end_headers()
                self.wfile.write(body)
        except Exception as e:
            self._deny(host, f"forward failed: {e}")

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _http

    @staticmethod
    def _tunnel(a, b):
        socks = [a, b]
        try:
            while True:
                r, _, x = select.select(socks, [], socks, 30)
                if x or not r:
                    break
                for s in r:
                    data = s.recv(8192)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        finally:
            for s in socks:
                try: s.close()
                except Exception: pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--port", type=int, default=8888)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    global SCOPE
    SCOPE = Scope.load(args.scope)
    print(f"[egress-proxy] scope={SCOPE.program} in={SCOPE.in_scope} "
          f"rate={SCOPE.rate_limit_rps}/s on {args.host}:{args.port}")
    ThreadingHTTPServer((args.host, args.port), Proxy).serve_forever()


if __name__ == "__main__":
    main()
