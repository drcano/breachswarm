#!/bin/bash
# Real-world demo: stand up a deliberately-vulnerable app and have the web
# specialist find and exploit it autonomously (live target, not static files).
# Proves the platform works for bug-bounty-style testing against a running host.
set -e
cd "$(dirname "$0")"

echo "[*] building vulnerable target..."
docker build -q -t vuln-target:latest targets/ >/dev/null

echo "[*] starting target on the docker bridge..."
docker rm -f vuln-target >/dev/null 2>&1 || true
docker run -d --rm --name vuln-target vuln-target:latest >/dev/null
sleep 3
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vuln-target)
echo "[*] target live at http://$IP:5000"

mkdir -p challenges/live/ssti_demo/files
cat > challenges/live/ssti_demo/challenge.json <<EOF
{
  "name": "live_ssti_demo",
  "category": "Web Exploitation",
  "prompt": "We stood up an internal build of StonksBot 3000. Find the hidden flag on the running service at http://$IP:5000/ . You are authorized to test this host.",
  "flag": "flag{ss7i_l1v3_t4rg3t_pwn3d}",
  "flag_pattern": "flag\\\\{[^}\\\\s]+\\\\}"
}
EOF

echo "[*] unleashing the web specialist (network on)..."
CTF_SANDBOX=docker ./.venv/bin/python run.py challenges/live --max-turns 20 -o results.live.jsonl

echo "[*] writeup: challenges/live/ssti_demo/writeup.md"
echo "[*] tearing down target..."
docker rm -f vuln-target >/dev/null 2>&1 || true
