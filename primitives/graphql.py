"""GraphQL primitive — introspect a GraphQL endpoint, surface the SENSITIVE surface, and hand back
the queries worth attacking. GraphQL hides a huge surface behind one endpoint: introspection reveals
every type/query/mutation (including ones no UI calls), objects are fetched by a global node id
(the BOLA vector), and alias/batching lets one request run hundreds of operations (rate-limit +
brute-force bypass). This does the introspection + triage in one call (through the sandbox proxy).

Introspection ALONE is not a finding (it's on the never-submit list) — this exists to turn it into
one: it flags the mutations/fields that, if unauthorized, ARE the bug (auth mutations, PII fields,
node(id:) BOLA), so the agent goes straight to testing access control, not just reporting "schema
readable".
"""
import base64
import json
import re

_SENSITIVE = re.compile(r"password|passwd|secret|token|api[_-]?key|ssn|credit|card|"
                        r"\bemail\b|phone|address|dob|salary|is_?admin|role|permission|"
                        r"private|internal|reset|impersonate|hash", re.I)
_MUTATION_HOT = re.compile(r"delete|update|create|set|grant|promote|reset|invite|refund|"
                           r"transfer|payout|role|admin|password|email|merge", re.I)

_INTROSPECT = ('{"query":"query{__schema{queryType{name} mutationType{name} '
               'types{name kind fields{name} }}}"}')


def analyze(introspection_json: str) -> tuple:
    """Parse an introspection response -> (findings:dict, summary). findings has sensitive fields,
    hot mutations, and node/BOLA hints — the surface to test for broken access control."""
    try:
        data = json.loads(introspection_json)
    except Exception:
        return {}, "graphql: introspection response was not JSON (endpoint may block introspection)."
    schema = (data.get("data") or {}).get("__schema") or {}
    types = schema.get("types") or []
    mut_type = (schema.get("mutationType") or {}).get("name")
    sensitive_fields, hot_mutations, node_bola = [], [], []
    for t in types:
        tname = t.get("name") or ""
        if tname.startswith("__"):
            continue
        for f in (t.get("fields") or []):
            fname = f.get("name") or ""
            if _SENSITIVE.search(fname):
                sensitive_fields.append(f"{tname}.{fname}")
            if tname == mut_type and _MUTATION_HOT.search(fname):
                hot_mutations.append(fname)
            if fname in ("node", "nodes") or fname.endswith("ById"):
                node_bola.append(f"{tname}.{fname}")
    findings = {"sensitive_fields": sorted(set(sensitive_fields))[:30],
                "hot_mutations": sorted(set(hot_mutations))[:30],
                "node_bola": sorted(set(node_bola))[:15],
                "n_types": len([t for t in types if not (t.get("name") or "").startswith("__")])}
    parts = [f"GraphQL introspection OK — {findings['n_types']} app types."]
    if findings["hot_mutations"]:
        parts.append("STATE-CHANGING mutations (test authz on each — an unauthorized one is the "
                     "finding): " + ", ".join(findings["hot_mutations"]))
    if findings["sensitive_fields"]:
        parts.append("SENSITIVE fields (query cross-user via node id / BOLA): "
                     + ", ".join(findings["sensitive_fields"]))
    if findings["node_bola"]:
        parts.append("node(id:) / *ById resolvers — swap another user's global id (authz_matrix): "
                     + ", ".join(findings["node_bola"]))
    if not (findings["hot_mutations"] or findings["sensitive_fields"]):
        parts.append("no obviously sensitive fields/mutations named — enumerate manually.")
    return findings, "\n  ".join(parts)


def run(sb, args: dict) -> str:
    url = args.get("url") or ""
    if not url.startswith("http"):
        return "graphql error: 'url' must be the absolute GraphQL endpoint (e.g. https://t/graphql)."
    headers = {}
    h = args.get("headers")
    if isinstance(h, dict):
        headers = {str(k): str(v) for k, v in h.items()}
    elif isinstance(h, str) and ":" in h:
        for line in h.replace("\\n", "\n").splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
    hdr = " ".join(f"-H {k}:{v!r}" for k, v in headers.items())
    q = args.get("query") or _INTROSPECT
    # single curl through the sandbox; -s so only the body comes back
    out = sb.bash(f"curl -s -m 20 -X POST {hdr} -H 'Content-Type: application/json' "
                  f"--data {q!r} {url!r}", timeout=60)
    findings, msg = analyze(out)
    if not findings:
        return msg + "\n(raw first 300 chars: " + (out or "")[:300] + ")"
    return msg


def demo() -> None:
    intro = json.dumps({"data": {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "User", "kind": "OBJECT", "fields": [
                {"name": "id"}, {"name": "email"}, {"name": "passwordHash"}, {"name": "role"}]},
            {"name": "Mutation", "kind": "OBJECT", "fields": [
                {"name": "login"}, {"name": "deleteUser"}, {"name": "resetPassword"}]},
            {"name": "Query", "kind": "OBJECT", "fields": [{"name": "node"}, {"name": "userById"}]},
            {"name": "__Type", "kind": "OBJECT", "fields": [{"name": "name"}]},  # meta -> ignored
        ]}}})
    f, msg = analyze(intro)
    assert "User.email" in f["sensitive_fields"] and "User.passwordHash" in f["sensitive_fields"]
    assert "User.role" in f["sensitive_fields"]
    assert set(f["hot_mutations"]) == {"deleteUser", "resetPassword"}, f["hot_mutations"]
    assert "Query.node" in f["node_bola"] and "Query.userById" in f["node_bola"]
    assert f["n_types"] == 3          # __Type excluded
    assert "STATE-CHANGING" in msg and "SENSITIVE" in msg
    # non-JSON (introspection disabled) handled
    assert analyze("<html>403</html>")[0] == {}
    print("graphql.py ok")


if __name__ == "__main__":
    demo()
