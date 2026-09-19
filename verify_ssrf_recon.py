"""Live self-check for the ssrf_recon exploit primitive (primitives/ssrf_recon.run).

Stands up a minimal Flask app on 5093 whose /fetch?url= endpoint SIMULATES a server-side
fetch (it never touches the real network): it reflects canned content for a few simulated
internal targets and an error otherwise. Points the primitive at it with the '/fetch?url={target}'
template and asserts it DISCOVERS, through the SSRF, the cloud-metadata endpoint (reporting the
leaked AccessKeyId) plus the internal redis and admin services — and marks a dead port unreachable.

Local socket only (no docker). Run: ./.venv/bin/python verify_ssrf_recon.py
"""
import sys, threading, time, subprocess
from urllib.parse import unquote
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from primitives import ssrf_recon

from flask import Flask, request

PORT = 5093
app = Flask(__name__)

_META = ('{"Code":"Success","AccessKeyId":"ASIAEXAMPLE1337","SecretAccessKey":"wJalr'
         'EXAMPLEKEY","SessionToken":"FQoGZ...","Type":"AWS-HMAC"}')
_REDIS = "-ERR unknown command\r\n# Server\r\nredis_version:6.2.7\r\nos:Linux\r\n"
_ADMIN = "<html><title>Internal Admin</title><body>admin console: user management</body></html>"


@app.route("/fetch")
def fetch():
    # Simulated SSRF: the server "fetches" url and reflects the body. No real network hit.
    url = unquote(request.args.get("url", ""))
    if "169.254.169.254" in url:
        body = _META
    elif ":6379" in url:
        body = _REDIS
    elif ":8080" in url:
        body = _ADMIN
    else:
        return '{"status":"error","detail":"could not fetch url: connection refused"}'
    # reflect the fetched content wrapped in the outer response, like a real preview/fetch API
    return '{"status":"ok","fetched":%s}' % __import__("json").dumps(body)


class HostSB:
    """Minimal sandbox shim: run the primitive's script on the host (python3 + base64 only)
    so it hits our in-process target."""
    def bash(self, cmd: str) -> str:
        return subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True,
                              timeout=180).stdout


def _serve():
    t = threading.Thread(target=lambda: app.run(port=PORT, threaded=True), daemon=True)
    t.start()
    time.sleep(1.2)


if __name__ == "__main__":
    _serve()
    ssrf = f"http://127.0.0.1:{PORT}/fetch?url={{target}}"

    out = ssrf_recon.run(HostSB(), {"ssrf_url": ssrf, "delay_between": 0.0})
    print(out.strip())

    assert "SSRF_RECON_OK" in out, "primitive did not complete"
    assert "ASIAEXAMPLE1337" in out, "did not surface the leaked AccessKeyId through the SSRF"
    assert "AccessKeyId" in out and "creds=" in out, "metadata creds not flagged as interesting"
    assert "redis_version:6.2.7" in out, "did not discover the internal redis service"
    assert "Internal Admin" in out, "did not discover the internal admin service"
    assert "169.254.169.254/latest/meta-data/" in out, "metadata target missing from map"
    # a port the simulator refuses must be reported unreachable, not a false positive
    assert "[--        ] http://127.0.0.1:3000/" in out, "dead port wrongly marked reachable"
    print("\n  ok  mapped metadata creds + redis + admin THROUGH the SSRF; dead port excluded")

    # arg guards
    assert "must contain the literal token {target}" in ssrf_recon.run(HostSB(),
        {"ssrf_url": "http://h/fetch?url="})
    assert "no targets to probe" in ssrf_recon.run(HostSB(),
        {"ssrf_url": ssrf, "targets": "   "})
    print("  ok  arg validation")

    # success_re + reflect_re path: extract inner body, custom reachability marker
    out2 = ssrf_recon.run(HostSB(), {
        "ssrf_url": ssrf, "delay_between": 0.0,
        "targets": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:3000/"],
        "reflect_re": r'"fetched":\s*(.*)\}\s*$', "success_re": "AccessKeyId"})
    assert "reachable=1/2" in out2, f"success_re/reflect_re path miscounted: {out2!r}"
    print("  ok  reflect_re extraction + success_re gating")

    print("\nssrf_recon verified: one call maps the internal surface through a reflected SSRF")
