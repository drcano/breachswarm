"""Shared per-engagement memory — the agent's state model across an ENTIRE run, so it infers
from what has already been scraped instead of re-deriving every turn (and every deeper stage
of a chain). Two kinds of state:

  surfaces: what recon learned about each attack surface (host:port) — tech, WAF, endpoints.
            Auto-populated by staged recon as the agent pivots to new surfaces.
  facts:    confirmed findings the agent records via note() — param names, encode depth, valid
            ids, tokens, roles, credentials — the things it currently re-derives from scratch.

Rendered compactly into context whenever it changes, so every later step builds on it. Keep it
small and factual: this is leverage (do less, stay quieter), not a scratch log.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse


def netloc_of(url: str) -> str:
    """host[:port] from a url or bare authority (scheme optional)."""
    p = urlparse(url if "//" in url else "//" + url.strip())
    return p.netloc


class Scratchpad:
    def __init__(self):
        self.surfaces: dict[str, dict] = {}
        self.facts: dict[str, str] = {}
        self._dirty = True                      # render once at the start of the run

    def has_surface(self, netloc: str) -> bool:
        return netloc in self.surfaces

    def add_surface(self, netloc: str, tech: str = "", waf: str = "", endpoints=None,
                    archetype: str = "", hunt=None, skip=None) -> None:
        if not netloc:
            return
        self.surfaces[netloc] = {"archetype": (archetype or "").strip()[:40],
                                 "tech": (tech or "").strip()[:200],
                                 "waf": (waf or "").strip()[:80],
                                 "endpoints": list(endpoints or [])[:10],
                                 "hunt": list(hunt or [])[:6], "skip": list(skip or [])[:6],
                                 "ts": round(time.time())}
        self._dirty = True

    def note(self, key: str, value: str) -> None:
        key = (key or "").strip()
        if key:
            self.facts[key] = (value or "").strip()[:300]
            self._dirty = True

    def changed(self) -> bool:
        """True (and clears) if state changed since last render — so we show deltas, not spam."""
        d, self._dirty = self._dirty, False
        return d

    def summary(self) -> str:
        """Lead with the TARGET ARCHITECTURE so the agent knows exactly what it is inside and
        never reconstructs context from scratch — per surface: what it is, its stack/WAF/routes,
        what to hunt, and what to skip. Then the confirmed facts to build on."""
        lines: list[str] = []
        if self.surfaces:
            lines.append("target architecture (known — do NOT re-recon or reconstruct):")
            for nl, s in self.surfaces.items():
                head = f"  {nl}" + (f"  [{s['archetype']}]" if s.get("archetype") else "")
                meta = [b for b in (s["tech"], (f"WAF:{s['waf']}" if s["waf"] else "")) if b]
                if meta:
                    head += "  " + " · ".join(meta)
                lines.append(head)
                if s["endpoints"]:
                    lines.append("     endpoints: " + " ".join(s["endpoints"]))
                if s.get("hunt"):
                    lines.append("     hunt: " + "; ".join(s["hunt"]))
                if s.get("skip"):
                    lines.append("     skip (don't spray these here): " + "; ".join(s["skip"]))
        if self.facts:
            lines.append("facts (confirmed — build on these):")
            for k, v in self.facts.items():
                lines.append(f"  {k} = {v}")
        return "\n".join(lines) or "(empty)"

    def dump(self) -> dict:
        return {"surfaces": self.surfaces, "facts": self.facts}


def demo() -> None:
    sp = Scratchpad()
    assert sp.changed() and not sp.changed()          # dirty once, then quiet
    sp.add_surface("10.0.0.9:8080", tech="Server: nginx", waf="cloudflare",
                   endpoints=["/admin", "/api"], archetype="REST-JSON API",
                   hunt=["IDOR/BOLA"], skip=["wordlist brute-force"])
    assert sp.has_surface("10.0.0.9:8080") and sp.changed()
    sp.note("param", "q"); sp.note("encode_depth", "3")
    assert sp.facts["encode_depth"] == "3" and sp.changed()
    s = sp.summary()
    assert "[REST-JSON API]" in s and "WAF:cloudflare" in s and "param = q" in s
    assert "hunt: IDOR/BOLA" in s and "skip" in s and "architecture" in s
    assert netloc_of("http://169.254.169.254/latest/meta-data/") == "169.254.169.254"
    assert netloc_of("host:5000") == "host:5000"
    print("scratchpad.py ok")


if __name__ == "__main__":
    demo()
