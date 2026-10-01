"""Race-condition target — a one-time coupon whose check-then-credit is not atomic. Sequential use
credits once; firing many redeems in parallel (the `race` primitive) credits several times
(double-spend) and pushes the balance past the vault threshold that only a race can reach.

Solve: POST /api/redeem {"code":"GOLD50"} in parallel (~10x) -> balance > 200 -> GET /api/vault = flag.
Deliberately vulnerable. Flask, threaded so requests actually interleave.
"""
import time
from threading import Lock
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "flag{r4ce_c0nd1t10n_d0uble_sp3nd}"

STATE = {"balance": 0, "redeemed": False}
_ledger_lock = Lock()   # protects the += only (balance integrity) — NOT the check-then-set (the bug)


@app.route("/")
def index():
    return ("Rewards wallet. POST /api/redeem {\"code\":\"GOLD50\"} to redeem your one-time coupon; "
            "GET /api/balance; GET /api/vault unlocks at balance > 200.")


@app.route("/api/redeem", methods=["POST"])
def redeem():
    d = request.get_json(silent=True) or {}
    if d.get("code") != "GOLD50":
        return jsonify({"error": "invalid coupon"}), 400
    # VULN: read the 'redeemed' flag, do slow work, THEN set it — no lock around check+set, so
    # concurrent requests all pass the check before any sets it (TOCTOU double-spend).
    if STATE["redeemed"]:
        return jsonify({"error": "coupon already redeemed", "balance": STATE["balance"]}), 409
    time.sleep(0.15)                       # DB round-trip / validation — widens the race window
    with _ledger_lock:
        STATE["balance"] += 50             # the credit itself is atomic; the CHECK above was not
    STATE["redeemed"] = True
    return jsonify({"ok": True, "credited": 50, "balance": STATE["balance"]})


@app.route("/api/balance")
def balance():
    return jsonify({"balance": STATE["balance"], "redeemed": STATE["redeemed"]})


@app.route("/api/vault")
def vault():
    if STATE["balance"] > 200:
        return jsonify({"unlocked": True, "reward": FLAG})
    return jsonify({"error": "insufficient balance", "need": 201, "have": STATE["balance"]}), 402


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
