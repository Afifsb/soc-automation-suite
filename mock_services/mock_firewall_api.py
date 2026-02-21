from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)


BLOCKED = {}  
AUDIT = []    

def now_ts() -> str:
    return datetime.now().isoformat(timespec="seconds")


@app.get("/blocked")
def list_blocked():
    return jsonify({"blocked": BLOCKED, "count": len(BLOCKED)})


@app.get("/audit")
def get_audit():
    # last 200 entries
    return jsonify({"audit": AUDIT[-200:], "count": len(AUDIT)})


@app.post("/block")
def block_ip():
    data = request.get_json(force=True) or {}
    ip = data.get("ip")
    reason = data.get("reason", "no reason provided")

    if not ip:
        return jsonify({"error": "ip is required"}), 400

    if ip in BLOCKED:
        AUDIT.append({"time": now_ts(), "action": "already_blocked", "ip": ip, "reason": reason})
        return jsonify({"status": "already_blocked", "ip": ip, "details": BLOCKED[ip]})

    BLOCKED[ip] = {"reason": reason, "time": now_ts()}
    AUDIT.append({"time": now_ts(), "action": "blocked", "ip": ip, "reason": reason})

    return jsonify({"status": "blocked", "ip": ip, "details": BLOCKED[ip]})


@app.post("/unblock")
def unblock_ip():
    data = request.get_json(force=True) or {}
    ip = data.get("ip")

    if not ip:
        return jsonify({"error": "ip is required"}), 400

    existed = ip in BLOCKED
    BLOCKED.pop(ip, None)

    AUDIT.append({"time": now_ts(), "action": "unblocked", "ip": ip, "reason": ""})
    return jsonify({"status": "unblocked", "ip": ip, "existed": existed})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5005, debug=True)
