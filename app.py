from flask import Flask, render_template,jsonify, request, abort
import pymongo
from bson import ObjectId
from datetime import datetime, timezone
import os, sys

sys.path.insert(0, os.path.dirname(__file__))

app = Flask(__name__)
client = pymongo.MongoClient("mongodb://localhost:27017/")
db     = client["threat_intel"]


# ─────────────────────────────────────────────
# Helper: serialize MongoDB docs (ObjectId → str, datetime → str)
# ─────────────────────────────────────────────
def serialize(docs):
    result = []
    for doc in docs:
        d = {}
        for k, v in doc.items():
            if isinstance(v, ObjectId):
                d[k] = str(v)
            elif isinstance(v, datetime):
                d[k] = v.strftime("%Y-%m-%d %H:%M UTC")
            else:
                d[k] = v
        result.append(d)
    return result


# ─────────────────────────────────────────────
# Main Dashboard
# ─────────────────────────────────────────────
@app.route("/")
def home():
    threats = serialize(
        list(db.indicators.find().sort("risk_score", -1).limit(100))
    )
    alerts = serialize(
        list(db.alerts.find().sort("timestamp", -1).limit(10))
    )
    audit_logs = serialize(
        list(db.audit_logs.find().sort("timestamp", -1).limit(20))
    )
    stats = {
        "total"        : db.indicators.count_documents({}),
        "blocked"      : db.indicators.count_documents({"status": "blocked"}),
        "high_risk"    : db.indicators.count_documents({"risk_score": {"$gte": 8}}),
        "rolled_back"  : db.indicators.count_documents({"status": "rolled_back"}),
        "unread_alerts": db.alerts.count_documents({"read": False})
    }
    return render_template("index.html",
                           threats=threats,
                           stats=stats,
                           alerts=alerts,
                           audit_logs=audit_logs)


# ─────────────────────────────────────────────
# API: Rollback an IP block
# ─────────────────────────────────────────────
@app.route("/api/rollback/<path:ip>", methods=["POST"])
def api_rollback(ip):
    """
    POST /api/rollback/1.2.3.4
    Triggers rollback for the given IP.
    Returns JSON: { success: bool, message: str }
    """
    from rollback import rollback_by_ip
    from alert_engine import alert_rollback_performed

    doc = db.indicators.find_one({"indicator": ip, "status": "blocked"})
    if not doc:
        return jsonify({"success": False, "message": f"No active block found for IP: {ip}"}), 404

    rule_id = doc.get("rule_id", "UNKNOWN")
    result  = rollback_by_ip(ip, triggered_by="manual_api")
    if result["success"]:
        alert_rollback_performed(ip, rule_id, triggered_by="manual_api")

    return jsonify(result)


# ─────────────────────────────────────────────
# API: Live Stats (for dashboard auto-refresh)
# ─────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():
    return jsonify({
        "total"        : db.indicators.count_documents({}),
        "blocked"      : db.indicators.count_documents({"status": "blocked"}),
        "high_risk"    : db.indicators.count_documents({"risk_score": {"$gte": 8}}),
        "rolled_back"  : db.indicators.count_documents({"status": "rolled_back"}),
        "unread_alerts": db.alerts.count_documents({"read": False}),
        "last_updated" : datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    })


# ─────────────────────────────────────────────
# API: Alerts feed
# ─────────────────────────────────────────────
@app.route("/api/alerts")
def api_alerts():
    limit  = int(request.args.get("limit", 20))
    alerts = serialize(list(db.alerts.find().sort("timestamp", -1).limit(limit)))
    return jsonify(alerts)


# ─────────────────────────────────────────────
# API: Mark alert as read
# ─────────────────────────────────────────────
@app.route("/api/alerts/<alert_id>/read", methods=["POST"])
def api_mark_read(alert_id):
    try:
        db.alerts.update_one({"_id": ObjectId(alert_id)}, {"$set": {"read": True}})
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400


# ─────────────────────────────────────────────
# API: Audit Log feed
# ─────────────────────────────────────────────
@app.route("/api/audit")
def api_audit():
    limit = int(request.args.get("limit", 50))
    logs  = serialize(list(db.audit_logs.find().sort("timestamp", -1).limit(limit)))
    return jsonify(logs)


# ─────────────────────────────────────────────
# API: Threat list (JSON, for external tools)
# ─────────────────────────────────────────────
@app.route("/api/threats")
def api_threats():
    limit   = int(request.args.get("limit", 100))
    threats = serialize(list(db.indicators.find().sort("risk_score", -1).limit(limit)))
    return jsonify(threats)


if __name__ == "__main__":
    print("[TIP] Starting Flask dashboard on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
