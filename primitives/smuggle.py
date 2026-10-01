"""HTTP request-smuggling / desync DETECTION primitive — the timing-differential probe (Burp/
Turbo-Intruder classic), detection ONLY. When a front-end and back-end disagree on where a request
ends (one honors Content-Length, the other Transfer-Encoding), an attacker can prepend bytes to the
NEXT visitor's request — a critical class. This does NOT weaponize (a real smuggled request would
poison other users); it only measures whether a crafted CL.TE / TE.CL probe makes the back-end HANG
waiting for bytes that never come, which is the safe signal that the two ends disagree.

ponytail: time-based detection over a raw socket (curl normalizes the headers we need to desync).
A hang is a STRONG lead, not proof — confirm carefully and report; do NOT run the differential-
response confirmation that serves a smuggled prefix to real traffic. Rate-limited by nature (2 probes).
"""
import socket
import ssl
import time
from urllib.parse import urlparse


def _probe(host: str, port: int, use_tls: bool, raw: bytes, timeout: float) -> tuple:
    """Send raw bytes, return (elapsed_seconds, got_response_bool). A timeout => the server is still
    waiting for the body it was told to expect (the desync tell)."""
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        t0 = time.time()
        s.sendall(raw)
        s.settimeout(timeout)
        try:
            data = s.recv(64)
            return time.time() - t0, bool(data)
        except socket.timeout:
            return time.time() - t0, False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _clte(host: str) -> bytes:
    # front-end uses Content-Length (4 = "1\r\nA\r\n"), back-end uses Transfer-Encoding and waits for
    # the terminating 0-chunk that never arrives -> back-end hangs if it honors TE (CL.TE desync).
    body = "1\r\nA\r\nX"
    return (f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(body)}\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n{body}").encode()


def _tecl(host: str) -> bytes:
    # back-end uses Content-Length and waits for bytes the front-end (TE) already terminated -> hang
    # if TE.CL. The chunk announces more than is sent.
    body = "0\r\n\r\nX"
    return (f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n{body}").encode()


def analyze(baseline: float, clte: tuple, tecl: tuple, timeout: float) -> tuple:
    """A probe that hangs (~timeout) while the baseline returned fast => the ends disagree on length."""
    hangs = []
    if clte[0] >= max(timeout - 1, baseline * 3) and not clte[1]:
        hangs.append("CL.TE (front-end Content-Length, back-end Transfer-Encoding)")
    if tecl[0] >= max(timeout - 1, baseline * 3) and not tecl[1]:
        hangs.append("TE.CL (front-end Transfer-Encoding, back-end Content-Length)")
    if hangs:
        return True, ("DESYNC LEAD — probe hung waiting for body while a normal request returned in "
                      f"{baseline:.2f}s: " + "; ".join(hangs) + ". The front/back-end disagree on "
                      "request length (request-smuggling class). Confirm carefully and report — do "
                      "NOT run the response-poisoning confirmation against shared traffic.")
    return False, (f"no desync detected — baseline {baseline:.2f}s, CL.TE {clte[0]:.2f}s, "
                   f"TE.CL {tecl[0]:.2f}s (both returned; ends agree on length).")


def run(sb, args: dict) -> str:
    # runs HOST-side (raw sockets, like browser_verify) — the URL must be in scope; the caller
    # (bounty tool) enforces scope.allows before calling.
    url = args.get("url") or ""
    u = urlparse(url if "://" in url else "http://" + url)
    host = u.hostname
    if not host:
        return "smuggle error: give a target URL/host."
    use_tls = (u.scheme == "https")
    port = u.port or (443 if use_tls else 80)
    timeout = float(args.get("timeout") or 8)
    try:
        base = _probe(host, port, use_tls, f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode(), timeout)
        clte = _probe(host, port, use_tls, _clte(host), timeout)
        tecl = _probe(host, port, use_tls, _tecl(host), timeout)
    except Exception as e:
        return f"smuggle: probe failed ({str(e)[:120]})."
    _, msg = analyze(base[0], clte, tecl, timeout)
    return "SMUGGLE PROBE " + msg


def demo() -> None:
    # baseline fast + CL.TE hung (no response, ~timeout) -> desync lead
    is_d, msg = analyze(0.2, (8.0, False), (0.3, True), 8)
    assert is_d and "CL.TE" in msg and "DESYNC LEAD" in msg, msg
    # both returned quickly -> clean
    assert not analyze(0.2, (0.25, True), (0.3, True), 8)[0]
    # TE.CL hang
    is_d2, msg2 = analyze(0.2, (0.25, True), (8.0, False), 8)
    assert is_d2 and "TE.CL" in msg2
    # a slow-but-answering probe (not a hang) is NOT flagged
    assert not analyze(0.2, (1.0, True), (1.0, True), 8)[0]
    print("smuggle.py ok")


if __name__ == "__main__":
    demo()
