"""System-wide model selection.

Every agent (recon, specialists, bounty, report, writeup) uses MODEL so the whole
system runs on one capable model. Override per run with the CTF_MODEL env var, e.g.:
    CTF_MODEL=claude-fable-5-1  ./.venv/bin/python run.py ...
    CTF_MODEL=claude-opus-5     ./.venv/bin/python bounty.py ...

Default is Opus (most capable general model — best for exploitation reasoning and
chaining). The diagnostic in docs/bounty_patterns.md showed model quality drives
recon map quality directly (haiku flailed, sonnet gave a prioritized map), so the
lethality test runs everything on the top model.
"""
import os

MODEL = os.getenv("CTF_MODEL", "claude-opus-4-8")
