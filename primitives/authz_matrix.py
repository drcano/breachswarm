"""Cross-user authorization matrix — an executable exploit PRIMITIVE (Autorize/AuthMatrix style).

The highest-paid web bugs are broken access control: a request that works for user A also works
for user B, or unauthenticated. Proving it means replaying ONE request across every auth context
and every resource id and spotting where the boundary fails. The agent can do this by hand, but
it's exactly the kind of stateful, N×M sweep a primitive should systematize: one call runs the
whole matrix (through the sandbox proxy, so scope + rate still apply) and flags the anomalies.

Anomalies flagged (leads to confirm, not confirmed findings):
  - ANON 2xx on a resource            -> authentication bypass
  - a non-owner auth gets 2xx (owner map given) -> broken object-level authz (BOLA/IDOR)
  - multiple users get 2xx, same size (no owner map) -> possible cross-user access

ponytail: the HTTP sweep is an in-sandbox stdlib script; the anomaly logic is analyze() here,
host-side and unit-tested — no duplicated heuristic.
"""
import base64
import json
import re


def _detect(id_str: str):
    """Detect a resource id's ENCODING so a sibling id can be forged in the SAME format.
    Returns (scheme, value) where value is what to increment:
      ("int", n) | ("hex", n) | ("b64", n) | ("node", (type_str, n)) | ("opaque", id_str).
    Opaque (uuid / random / non-numeric) has no meaningful neighbor."""
    s = id_str.strip()
    if re.fullmatch(r"\d+", s):
        return ("int", int(s))
    if re.fullmatch(r"0x[0-9a-fA-F]+", s):
        return ("hex", int(s, 16))
    # base64 (padded) that decodes cleanly
    if re.fullmatch(r"[A-Za-z0-9+/]{4,}={0,2}", s) and len(s) % 4 == 0:
        try:
            dec = base64.b64decode(s, validate=True).decode("utf-8", "strict")
        except Exception:
            dec = None
        if dec is not None:
            m = re.fullmatch(r"([A-Za-z][\w.-]*):(\d+)", dec)   # GraphQL global node id "Type:123"
            if m:
                return ("node", (m.group(1), int(m.group(2))))
            if re.fullmatch(r"\d+", dec):                        # base64 of a plain number
                return ("b64", int(dec))
    return ("opaque", id_str)


def _encode(scheme, value) -> str:
    if scheme == "int":  return str(value)
    if scheme == "hex":  return "0x%x" % value
    if scheme == "b64":  return base64.b64encode(str(value).encode()).decode()
    if scheme == "node":
        t, n = value
        return base64.b64encode(f"{t}:{n}".encode()).decode()
    return str(value)


def id_variants(id_str: str, span: int = 2) -> list:
    """Sibling ids in the SAME encoding as id_str (the BOLA/IDOR neighbor probe): decode -> step the
    numeric part +/-span -> re-encode. Opaque ids (uuid/random) yield [] — you can't guess a neighbor.
    Excludes id_str itself; never emits negatives."""
    scheme, value = _detect(id_str)
    if scheme == "opaque":
        return []
    base = value[1] if scheme == "node" else value
    out = []
    for k in range(-span, span + 1):
        if k == 0:
            continue
        n = base + k
        if n < 0:
            continue
        out.append(_encode(scheme, (value[0], n) if scheme == "node" else n))
    return out



def _script(params: dict) -> str:
    return "import json,time,urllib.request,urllib.error\n" + \
           f"P=json.loads(r'''{json.dumps(params)}''')\n" + r'''
URL=P["url"]; METHOD=P.get("method","GET"); AUTHS=P["auths"]; IDS=P["ids"]
TIMEOUT=float(P.get("timeout",8)); DELAY=float(P.get("delay",0.3))
def req(u,header):
    r=urllib.request.Request(u,method=METHOD)
    if header and ":" in header:
        k,v=header.split(":",1); r.add_header(k.strip(),v.strip())
    try:
        resp=urllib.request.urlopen(r,timeout=TIMEOUT); return resp.getcode(),len(resp.read())
    except urllib.error.HTTPError as e:
        try: n=len(e.read())
        except Exception: n=0
        return e.code,n
    except Exception:
        return 0,0
for name,header in AUTHS.items():
    for i in IDS:
        st,ln=req(URL.replace("{id}",str(i)),header)
        print("RESULT %s|%s|%s|%s"%(name,i,st,ln)); time.sleep(DELAY)
print("AUTHZ_MATRIX_DONE")
'''


def analyze(matrix: dict, ids: list, auths: list, owner: dict | None = None,
            admins: list | None = None, victims: set | None = None) -> tuple[list, str]:
    """matrix: {(auth,id): (status,length)}. `admins` are contexts EXPECTED to access everything
    (a site admin reading any object is documented behavior, not a finding). `victims` are FORGED
    neighbor ids (id-transform) that the tester does NOT own — a SINGLE non-admin 2xx on one is a
    BOLA candidate (no same-size heuristic needed, it isn't the tester's object). Returns
    (anomalies, rendered_table)."""
    def ok(st):
        return isinstance(st, int) and 200 <= st < 300
    admins = set(admins or [])
    victims = set(str(v) for v in (victims or []))
    anomalies, rows = [], []
    for i in ids:
        cells = {a: matrix.get((a, str(i)), matrix.get((a, i), (None, None))) for a in auths}
        succ = [a for a in auths if ok(cells[a][0])]
        rows.append("  id %-14s " % i +
                    "  ".join(f"{a}={cells[a][0]}({cells[a][1]})" for a in auths))
        anon_succ = [a for a in succ if a.lower() in ("anon", "unauth", "none", "")]
        if anon_succ:
            anomalies.append(f"AUTH BYPASS: id {i} returns 2xx UNAUTHENTICATED ({anon_succ})")
        if victims and str(i) in victims:            # a forged neighbor id — not the tester's object
            intruders = [a for a in succ if a not in anon_succ and a not in admins]
            if intruders:
                anomalies.append(f"BOLA/IDOR: forged neighbor id {i} is 2xx for non-owner "
                                 f"{intruders} — the tester does not own it (broken object-level authz)")
        elif owner and (str(i) in owner or i in owner):
            legit = owner.get(str(i), owner.get(i))
            intruders = [a for a in succ if a != legit and a not in anon_succ and a not in admins]
            if intruders:
                anomalies.append(f"BROKEN AUTHZ: id {i} is owned by {legit} but also 2xx for "
                                 f"{intruders} (BOLA/IDOR)")
        else:
            non_anon = [a for a in succ if a not in anon_succ and a not in admins]
            if len(non_anon) > 1:
                sizes = [cells[a][1] for a in non_anon]
                if max(sizes) - min(sizes) <= 5:      # same-ish body -> same resource, not per-user
                    anomalies.append(f"POSSIBLE CROSS-USER: id {i} readable by multiple non-admin "
                                     f"users {non_anon} with same response size — confirm ownership")
    table = "auth-matrix (status(size) per auth context):\n" + "\n".join(rows)
    return anomalies, table


def run(sb, args: dict) -> str:
    url = args.get("url") or ""
    if "{id}" not in url:
        return ("authz_matrix error: 'url' must contain the literal token {id}, e.g. "
                "'https://host/api/users/{id}'.")
    try:
        auths = json.loads(args["auths"]) if isinstance(args.get("auths"), str) else args.get("auths")
    except Exception:
        return ("authz_matrix error: 'auths' must be a JSON object of name->header, e.g. "
                "'{\"A\":\"Authorization: Bearer x\",\"B\":\"Authorization: Bearer y\",\"anon\":\"\"}'.")
    if not auths:
        return "authz_matrix error: need at least one auth context in 'auths'."
    ids = [s.strip() for s in str(args.get("ids", "")).replace(",", "\n").splitlines() if s.strip()]
    if not ids:
        return "authz_matrix error: 'ids' is empty (comma-separated resource ids to sweep)."
    victims = set()
    span = int(args.get("neighbors") or 0)           # id-transform: forge neighbor ids in the SAME encoding
    if span > 0:
        seed = list(ids)
        for sid in seed:
            for v in id_variants(sid, span):
                if v not in ids:
                    ids.append(v); victims.add(v)
    owner = None
    if args.get("owner"):
        try:
            owner = json.loads(args["owner"]) if isinstance(args["owner"], str) else args["owner"]
        except Exception:
            owner = None
    admins = [s.strip() for s in str(args.get("admins", "")).replace(",", "\n").splitlines()
              if s.strip()]
    params = {"url": url, "method": (args.get("method") or "GET").upper(), "auths": auths,
              "ids": ids, "timeout": float(args.get("timeout") or 8),
              "delay": float(args.get("delay") or 0.3)}
    b64 = base64.b64encode(_script(params).encode()).decode()
    out = sb.bash(f"echo {b64} | base64 -d | python3 -", timeout=180)
    matrix = {}
    for line in out.splitlines():
        if line.startswith("RESULT "):
            try:
                name, i, st, ln = line[len("RESULT "):].split("|")
                matrix[(name, i)] = (int(st), int(ln))
            except Exception:
                pass
    if not matrix:
        return "authz_matrix: no results parsed — sandbox output:\n" + out[:500]
    anomalies, table = analyze(matrix, ids, list(auths), owner, admins, victims)
    head = ("AUTHZ_MATRIX " + ("!! %d ANOMALY(S) — confirm these" % len(anomalies) if anomalies
            else "clean: no cross-user/anon access detected"))
    return head + "\n" + ("\n".join("  ‼ " + a for a in anomalies) + "\n" if anomalies else "") + table


def demo() -> None:
    ids = [1, 2]
    auths = ["A_admin", "B_user", "anon"]
    # A owns 1&2 (admin); B gets its own 2 AND A's 1 (same size 500) = BOLA; anon 401
    m = {("A_admin", "1"): (200, 500), ("A_admin", "2"): (200, 500),
         ("B_user", "1"): (200, 500), ("B_user", "2"): (200, 500),
         ("anon", "1"): (401, 0), ("anon", "2"): (401, 0)}
    an, table = analyze(m, ids, auths, owner={"1": "A_admin", "2": "B_user"}, admins=["A_admin"])
    assert any("BROKEN AUTHZ: id 1" in a and "B_user" in a for a in an), an
    assert not any("id 2" in a for a in an), an            # admin A reading id 2 is expected
    # heuristic mode (no owner map): id 1 readable by both users, same size -> flagged
    an2, _ = analyze(m, ids, auths, owner=None)
    assert any("CROSS-USER: id 1" in a for a in an2), an2
    # anon bypass
    m2 = {("anon", "9"): (200, 42)}
    an3, _ = analyze(m2, [9], ["anon"], owner=None)
    assert any("AUTH BYPASS: id 9" in a for a in an3), an3
    # fully hardened -> no anomalies
    m3 = {("A_admin", "1"): (200, 500), ("B_user", "1"): (403, 0), ("anon", "1"): (401, 0)}
    an4, _ = analyze(m3, [1], auths, owner={"1": "A_admin"})
    assert an4 == [], an4
    # id-transform: neighbors in the SAME encoding
    assert id_variants("123", 1) == ["122", "124"], id_variants("123", 1)
    assert _detect("MTIz") == ("b64", 123)                       # base64("123")
    assert "MTI0" in id_variants("MTIz", 1)                      # base64("124")
    nd = _detect("VXNlcjoxMjM=")                                 # base64("User:123")
    assert nd == ("node", ("User", 123)), nd
    import base64 as _b
    assert _b.b64decode(id_variants("VXNlcjoxMjM=", 1)[0]).decode() in ("User:122", "User:124")
    assert id_variants("0x10", 1) == ["0xf", "0x11"]
    assert id_variants("550e8400-e29b-41d4-a716-446655440000") == []   # opaque uuid -> no neighbor
    assert id_variants("0") == ["1", "2"]                        # never negative
    # victims: a single non-admin 2xx on a forged neighbor id = BOLA (no owner map needed)
    mv = {("B_user", "124"): (200, 300), ("B_user", "123"): (200, 300)}
    an5, _ = analyze(mv, ["123", "124"], ["B_user"], victims={"124"})
    assert any("forged neighbor id 124" in a for a in an5), an5
    assert not any("123" in a for a in an5), an5                 # tester's own id not flagged
    print("authz_matrix.py ok")


if __name__ == "__main__":
    demo()
