"""Professional vulnerability report generator — models real HackerOne/Bugcrowd
report structure so findings read as a triager expects.

One LLM pass over the run's audit trace produces: an executive summary table, then
one detailed finding per vulnerability with the canonical sections (title, CVSS
severity + vector + justification, CWE, affected asset, numbered repro/PoC, impact,
remediation, references). Grounded in a CWE/CVSS reference so severity isn't guessed.
"""
from __future__ import annotations
from config import MODEL

from claude_agent_sdk import query, ClaudeAgentOptions
from writeup import _render, _fallback

# Common web-vuln classes -> (CWE, a sane baseline CVSS 3.1 vector + band). The
# model adjusts per demonstrated impact, but this anchors it to real taxonomy.
REF = {
    "sqli":     ("CWE-89",  "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)"),
    "cmdi":     ("CWE-78",  "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)"),
    "ssti":     ("CWE-1336","Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)"),
    "ssrf":     ("CWE-918", "High",     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N (7.6)"),
    "idor":     ("CWE-639", "High",     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5)"),
    "auth":     ("CWE-287", "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)"),
    "jwt":      ("CWE-347", "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)"),
    "crypto":   ("CWE-347", "High",     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N (8.2)"),
    "misconfig":("CWE-16",  "Medium",   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)"),
    "xss":      ("CWE-79",  "Medium",   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1)"),
    "traversal":("CWE-22",  "High",     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)"),
    "llm_injection":  ("CWE-1427","High","CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N (8.2)"),
    "excessive_agency":("CWE-250","High","CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N (8.5)"),
}

_REF_TXT = "\n".join(f"  {k}: {cwe}, baseline {sev} — {vec}" for k, (cwe, sev, vec) in REF.items())

REPORT_SYS = (
    "You are a senior security researcher writing a professional vulnerability "
    "report for a bug-bounty program (HackerOne/Bugcrowd style). You are given the "
    "target and the FULL audit trace of an authorized test. Write a report a triager "
    "can act on in under 10 minutes. Ground every claim in the trace — never invent a "
    "finding that isn't evidenced.\n\n"
    "STRUCTURE:\n"
    "# Vulnerability Assessment — <target>\n"
    "## Executive Summary  — 2-3 sentences + a table: | # | Finding | Severity | CWE |\n"
    "Then, for EACH confirmed vulnerability, a section:\n"
    "### <N>. <Title formula: [bug class] in [exact endpoint] allows [attacker role] to "
    "[impact] [victim scope]>\n"
    "<ONE plain-English sentence stating exactly what an attacker CAN do — the impact-first "
    "opener a triager reads before anything else.>\n"
    "- **Severity:** <band> — <CVSS vector (score)>\n"
    "- **CWE:** <id + name>\n"
    "- **Affected asset:** <exact URL/endpoint/parameter>\n"
    "- **Steps to Reproduce:** numbered, exact, copy-pasteable, with full URLs, the exact "
    "request(s), and the observed response evidence from the trace. When the bug is cross-account, "
    "start with a `Setup:` line naming the two accounts (Account A = attacker, Account B = victim) "
    "and end the steps with an `Expected: <403/rejected>  Actual: <200 with B's data>` line.\n"
    "- **Impact:** <worst realistic outcome, quantified — records/users/data; note any chaining>\n"
    "- **Remediation:** <root-cause fix, 1-2 sentences>\n"
    "- **References:** CWE link + OWASP\n\n"
    "WRITING RULES (bounty triager standard): impact first; first person, active voice; NO hedging "
    "words — never 'could', 'may', 'might', 'potentially', 'in theory'. State only what the trace "
    "concretely PROVES and omit anything it does not. No vuln-class lectures. Keep each finding "
    "under ~600 words.\n"
    "Only include findings actually demonstrated in the trace. Match severity to the "
    "DEMONSTRATED impact (no inflated criticals). End with a short 'Coordinated "
    "Disclosure' note (no public disclosure before a fix; standard 90-day window).\n\n"
    "CWE/CVSS reference to anchor severity (adjust per demonstrated impact):\n" + _REF_TXT
)


async def generate_report(program: str, target: str, trace: list[dict]) -> str:
    task = (f"Program: {program}\nTarget: {target}\n\n"
            f"Audit trace of the authorized test:\n\n{_render(trace)}")
    md = []
    try:
        async for msg in query(prompt=task,
                               options=ClaudeAgentOptions(system_prompt=REPORT_SYS, max_turns=3, model=MODEL)):
            for b in getattr(msg, "content", []) or []:
                if t := getattr(b, "text", None):
                    md.append(t)
    except Exception as e:
        return _fallback(f"report:{program}", f"Target {target}", trace, True, None, e)
    return "\n".join(md) or _fallback(f"report:{program}", f"Target {target}", trace, True, None, None)
