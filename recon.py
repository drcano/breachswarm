"""Recon pass — runs BEFORE the specialist, in the same sandbox.

Cheap, deterministic shell probes (no LLM) that (1) sharpen routing when the
challenge has no category label and (2) hand the specialist a ready-made brief
so it starts informed instead of rediscovering the filesystem.

D-CIPHER calls this role the "auto-prompter"; here it's mostly `file`+`strings`.
"""
from __future__ import annotations

import re

# file(1) / extension signals -> specialist key. First match wins.
_SIGNALS: list[tuple[str, str]] = [
    (r"ELF |PE32|Mach-O|executable", "rev"),
    (r"pcap|tcpdump|capture file", "forensics"),
    (r"image data|PNG|JPEG|bitmap|GIF|TIFF", "forensics"),
    (r"Zip archive|gzip|tar archive|7-zip|POSIX tar|RAR", "forensics"),
    (r"memory dump|Windows crash|ELF core", "forensics"),
    (r"PEM |RSA |OpenSSH|certificate|private key", "crypto"),
]
_CRYPTO_TEXT = re.compile(r"-----BEGIN|[A-Fa-f0-9]{64,}|^[A-Za-z0-9+/=]{40,}$", re.M)
_URL = re.compile(r"https?://[^\s\"'>]+")


def recon(sb, prompt: str = "") -> dict:
    """Return a brief: {listing, files:[{name,type}], target_url, suggested, notes}."""
    listing = sb.bash("ls -la")
    ftypes = sb.bash("file * 2>/dev/null").strip()
    files = []
    for line in ftypes.splitlines():
        if ":" in line:
            name, _, desc = line.partition(":")
            files.append({"name": name.strip(), "type": desc.strip()})

    # a small strings sample from any binary/data file, for the brief
    sample = sb.bash("for f in *; do [ -f \"$f\" ] && strings -n 6 \"$f\" 2>/dev/null "
                     "| head -20; done | head -60")

    suggested = _classify(prompt, ftypes, sample)
    target = _URL.search(prompt)
    return {
        "listing": listing.strip(),
        "files": files,
        "target_url": target.group(0) if target else None,
        "suggested": suggested,
        "sample": sample.strip()[:2000],
        "probe": _deep_probe(sb, suggested).strip()[:2500],
    }


# Category-aware deterministic probes — cheap intel that primes the specialist.
# All tool-guarded (2>/dev/null / `|| true`) so a missing tool never errors.
_PROBES = {
    "rev": r"""for f in *; do [ -f "$f" ] || continue; if file "$f" | grep -qE 'ELF|PE32|Mach-O'; then echo "== $f =="; (checksec --file="$f" 2>/dev/null || pwn checksec "$f" 2>/dev/null) | head -8; readelf -h "$f" 2>/dev/null | grep -E 'Class|Machine|Type:'; fi; done""",
    "pwn": r"""for f in *; do [ -f "$f" ] || continue; if file "$f" | grep -qE 'ELF'; then echo "== $f =="; (checksec --file="$f" 2>/dev/null || pwn checksec "$f" 2>/dev/null) | head -8; fi; done""",
    "forensics": r"""for f in *; do [ -f "$f" ] || continue; case "$f" in *.pcap|*.pcapng) echo "== $f (protocols) =="; tshark -r "$f" -q -z io,phs 2>/dev/null | head -25;; *.png|*.bmp) echo "== $f (zsteg) =="; zsteg -a "$f" 2>/dev/null | head -12;; *.jpg|*.jpeg) echo "== $f (exif) =="; exiftool "$f" 2>/dev/null | grep -iE 'comment|artist|gps|software|xmp' | head;; *.zip|*.7z|*.tar*|*.gz) echo "== $f (contents) =="; 7z l "$f" 2>/dev/null | head -15;; esac; done""",
    "crypto": r"""for f in *; do [ -f "$f" ] || continue; case "$f" in *.txt|*.pem|*.pub|*.key|*.enc) echo "== $f =="; head -c 400 "$f"; echo;; esac; done; grep -rlE 'BEGIN (RSA|PUBLIC|PRIVATE)' . 2>/dev/null | head""",
    "web": "",  # target-driven; specialist probes the live host
    "misc": "",
}


def _deep_probe(sb, suggested: str) -> str:
    cmd = _PROBES.get(suggested, "")
    return sb.bash(cmd) if cmd else ""


def _classify(prompt: str, ftypes: str, sample: str) -> str:
    if _URL.search(prompt):
        return "web"
    for pat, cat in _SIGNALS:
        if re.search(pat, ftypes):
            return cat
    if _CRYPTO_TEXT.search(sample):
        return "crypto"
    return "misc"


def demo() -> None:
    assert _classify("go pwn http://host:1234/", "", "") == "web"
    assert _classify("", "chall: ELF 64-bit LSB executable", "") == "rev"
    assert _classify("", "dump.pcap: pcap capture file", "") == "forensics"
    assert _classify("", "photo.png: PNG image data", "") == "forensics"
    assert _classify("", "key.pem: unknown", "-----BEGIN RSA PRIVATE KEY-----") == "crypto"
    assert _classify("just a riddle", "notes.txt: ASCII text", "hello world") == "misc"
    print("recon.py ok")


def brief_text(r: dict) -> str:
    """Render the brief for injection into the specialist's opening prompt."""
    lines = ["## Recon brief (gathered before you started)",
             "Files present:"]
    lines += [f"  - {f['name']}: {f['type']}" for f in r["files"]] or ["  (none detected)"]
    if r["target_url"]:
        lines.append(f"Target URL: {r['target_url']}")
    if r.get("probe"):
        lines.append(f"Category probe:\n{r['probe']}")
    if r["sample"]:
        lines.append(f"Notable strings:\n{r['sample']}")
    return "\n".join(lines)


if __name__ == "__main__":
    demo()
