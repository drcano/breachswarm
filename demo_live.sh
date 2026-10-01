#!/bin/bash
# Real-world demo: stand up deliberately-vulnerable apps and have the web
# specialist find and exploit them autonomously against a LIVE service (no local
# files) — the bug-bounty setup. Proves the platform beyond static CTF challenges.
#
# Usage: ./demo_live.sh [ssti|sqli|both]   (default: both)
set -e
cd "$(dirname "$0")"
WHICH="${1:-both}"

docker build -q -t vuln-target:latest targets/ >/dev/null

run_demo() {  # name  app-file  flag
  local name="$1" app="$2" flag="$3"
  echo "[*] === $name ==="
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --rm --name "$name" -e APP="$app" vuln-target:latest >/dev/null
  sleep 3
  local ip; ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")
  echo "[*] target live at http://$ip:5000"
  local dir="challenges/live/$name"; mkdir -p "$dir/files"
  ./.venv/bin/python - "$dir/challenge.json" "$name" "$ip" "$flag" <<'PY'
import json, sys
path, name, ip, flag = sys.argv[1:5]
json.dump({
    "name": name, "category": "Web Exploitation",
    "prompt": f"Authorized test: recover the hidden flag from the StonksBot "
              f"service running at http://{ip}:5000/ (endpoints include /login "
              f"and /greet).",
    "flag": flag, "flag_pattern": r"flag\{[^}\s]+\}",
}, open(path, "w"), indent=2)
PY
  rm -rf "/tmp/$name" && mkdir -p "/tmp/$name" && ln -s "$(pwd)/$dir" "/tmp/$name/c"
  CTF_SANDBOX=docker ./.venv/bin/python run.py "/tmp/$name" --max-turns 25 -o "results.$name.jsonl"
  echo "[*] writeup: $dir/writeup.md"
  docker rm -f "$name" >/dev/null 2>&1 || true
}

[ "$WHICH" = "ssti" ] || [ "$WHICH" = "both" ] && run_demo ssti_demo vuln_app.py  'flag{ss7i_l1v3_t4rg3t_pwn3d}'
[ "$WHICH" = "sqli" ] || [ "$WHICH" = "both" ] && run_demo sqli_demo vuln_sqli.py 'flag{sql1_dump3d_by_the_agent}'
echo "[*] done."
