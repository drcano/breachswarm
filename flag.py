"""Flag detection — the auto-terminate core of the solver.

The flag format IS the verifier: if a specialist's output contains a string
matching the challenge's flag regex, the solve loop stops. No LLM needed for
the primary check.
"""
import re

# Common CTF flag shapes. A specific challenge overrides with its own regex.
# Flag bodies never contain whitespace or backticks; excluding them stops the
# extractor from matching the agent's *prose about* a flag (e.g. "picoCTF{` ... `}")
# and auto-terminating on garbage before the real solve.
DEFAULT_FLAG_RE = re.compile(r"(?:flag|ctf|pico|[A-Za-z0-9_]{2,10})\{[^}\s`]{1,200}\}")


# Obvious non-answers the model writes when talking *about* the flag format.
_PLACEHOLDERS = {"...", "…", "flag", "flaghere", "flag_here", "xxx", "example",
                 "redacted", "your_flag_here", "insert_flag_here"}


def _is_placeholder(flag: str) -> bool:
    body = flag[flag.find("{") + 1:flag.rfind("}")].strip().lower()
    return body in _PLACEHOLDERS or "..." in body or "…" in body


def find_flag(text: str, pattern: str | None = None) -> str | None:
    """Return the first real flag-shaped substring in `text`, skipping obvious
    placeholders the model emits when describing the format."""
    rx = re.compile(pattern) if pattern else DEFAULT_FLAG_RE
    for m in rx.finditer(text or ""):
        if not _is_placeholder(m.group(0)):
            return m.group(0)
    return None


def is_correct(candidate: str | None, real_flag: str | None) -> bool:
    """Strict scoring — what picoCTF's checker actually does (case-sensitive,
    exact). If no real flag is given, a well-formed match is a solve (live mode)."""
    if not candidate:
        return False
    if real_flag:
        return candidate.strip() == real_flag.strip()
    return True


def is_near_miss(candidate: str | None, real_flag: str | None) -> bool:
    """True when the solver cracked it but got the case wrong (classical ciphers
    output uppercase; picoCTF gold is lowercase). Diagnostic, not a solve:
    separates 'couldn't solve' from 'solved, fumbled the format'."""
    if not candidate or not real_flag:
        return False
    c, r = candidate.strip(), real_flag.strip()
    return c != r and c.lower() == r.lower()


def demo() -> None:
    assert find_flag("junk\nflag{h3llo_w0rld} more") == "flag{h3llo_w0rld}"
    assert find_flag("picoCTF{a_b_c}") == "picoCTF{a_b_c}"
    assert find_flag("no flag here") is None
    assert find_flag("KEY{xyz}", pattern=r"KEY\{[^}]+\}") == "KEY{xyz}"
    assert is_correct("flag{x}", "flag{x}") is True
    assert is_correct("flag{x}", "flag{y}") is False
    assert is_correct("flag{x}", None) is True          # live mode: shape is enough
    assert is_correct(None, None) is False
    # near-miss: cracked but mis-formatted
    # placeholders are not real flags
    assert find_flag("the flag is picoCTF{...}") is None
    assert find_flag("submit picoCTF{your_flag_here}") is None
    assert find_flag("picoCTF{r34l_0ne} not picoCTF{...}") == "picoCTF{r34l_0ne}"
    assert is_near_miss("PICOCTF{THENUMBERSMASON}", "picoCTF{thenumbersmason}") is True
    assert is_near_miss("flag{x}", "flag{x}") is False   # strict solve, not a near-miss
    assert is_near_miss("picoCTF{wrong}", "picoCTF{right}") is False
    print("flag.py ok")


if __name__ == "__main__":
    demo()
