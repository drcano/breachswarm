"""Browser-verify — render a page in a real browser and tell XSS EXECUTION from ESCAPING.

The REST agent is blind to the render-context class (stored/DOM XSS that only fires when a browser
parses the response). This renders a URL in headless Chrome (`--dump-dom` runs the page's JS and
prints the post-JS DOM) and checks whether a planted payload EXECUTED. Flow: the agent plants a
payload that, on execution, writes a unique marker into the DOM (e.g. an onerror handler that sets
`document.documentElement.dataset.xss = '<marker>'`), then calls browser_verify(url, marker). Marker
present in the rendered DOM => the payload executed => stored/DOM XSS confirmed.

Reuses the installed Chrome (no headless-browser dependency). Runs host-side in the bounty runner,
so — like the oob tool — it is not behind the sandbox egress proxy; it renders ONE in-scope page.
ponytail: --dump-dom snapshot, not a full CDP driver. If you need console/network/interaction,
graduate to Playwright.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time


def chrome_bin() -> str:
    """Locate a Chrome/Chromium binary, or '' if none."""
    env = os.getenv("CHROME_BIN")
    if env and os.path.exists(env):
        return env
    mac = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if os.path.exists(mac):
        return mac
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome"):
        p = shutil.which(name)
        if p:
            return p
    return ""


def verdict(dom: str, marker: str, live_hint: str = "") -> str:
    """Interpret a rendered DOM. `marker` is the unique string the payload writes ON EXECUTION;
    `live_hint` (optional) is a substring that, if present, means the payload became live HTML."""
    dom = dom or ""
    if marker and marker in dom:
        return f"XSS EXECUTED — marker '{marker}' is present in the post-JS DOM. Confirmed."
    if live_hint and live_hint in dom:
        return (f"PARSED AS LIVE HTML — '{live_hint}' rendered as markup (not escaped), but the "
                f"execution marker did not appear. Likely XSS; adjust the payload's side effect.")
    return "NO EXECUTION — payload was escaped or inert (marker absent, no live injected markup)."


def render(url: str, timeout: float = 25.0) -> tuple[bool, str]:
    """(ok, dom_or_error). Headless Chrome `--dump-dom` prints the post-JS DOM then often does NOT
    exit (child GPU/renderer processes keep stdout open, so waiting for EOF hangs). So: read stdout
    incrementally until we see </html>, then kill the whole process group. Throwaway profile per
    call avoids the profile-lock hang on concurrent runs."""
    cb = chrome_bin()
    if not cb:
        return False, "no Chrome/Chromium binary found (set CHROME_BIN)"
    prof = tempfile.mkdtemp(prefix="bv_prof_")
    cmd = [cb, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
           "--no-default-browser-check", "--disable-extensions", f"--user-data-dir={prof}",
           "--virtual-time-budget=3000", "--dump-dom", url]
    p = None
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             start_new_session=True)
        os.set_blocking(p.stdout.fileno(), False)
        buf, deadline = b"", time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = os.read(p.stdout.fileno(), 65536)
            except BlockingIOError:
                chunk = b""
            if chunk:
                buf += chunk
                if b"</html>" in buf.lower():        # full DOM captured — stop waiting
                    break
            elif p.poll() is not None:                # exited on its own
                break
            else:
                time.sleep(0.15)
        dom = buf.decode("utf-8", "replace")
        if dom.strip():
            return True, dom
        return False, f"render produced no DOM within {timeout}s"
    except Exception as e:
        return False, f"render failed: {e}"
    finally:
        if p is not None:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception:
                pass
        shutil.rmtree(prof, ignore_errors=True)


def verify(url: str, marker: str = "", live_hint: str = "", timeout: float = 25.0) -> str:
    ok, dom = render(url, timeout)
    if not ok:
        return f"browser_verify: {dom}"
    return verdict(dom, marker, live_hint)


def demo() -> None:
    executed = "<html data-xss=\"FIRED-EXEC\"><body>...</body></html>"
    escaped = "<html><body>&lt;img src=x onerror=...&gt;</body></html>"
    live = "<html><body><svg onload=x></svg></body></html>"
    assert "EXECUTED" in verdict(executed, "FIRED-EXEC")
    assert "NO EXECUTION" in verdict(escaped, "FIRED-EXEC")
    assert "NO EXECUTION" in verdict(escaped, "FIRED-EXEC", live_hint="<svg onload")
    assert "LIVE HTML" in verdict(live, "FIRED-EXEC", live_hint="<svg onload")
    print("browser_verify.py ok — chrome:", chrome_bin() or "NONE")


if __name__ == "__main__":
    demo()
