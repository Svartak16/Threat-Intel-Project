"""
audit_log.py - Week 3
Centralized audit trail for all enforcement and rollback actions.
Every block/unblock is recorded in MongoDB 'audit_logs' collection.
"""
import pymongo
from datetime import datetime, timezone
import uuid

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
audit_collection = db["audit_logs"]

def log_action(action: str, ip: str, rule_id: str, reason: str, triggered_by: str = "auto_enforcer", extra: dict = None):
    """
    Write an audit entry to MongoDB FOR GIVEN IP ADDRESS

    Args:
        action      : "BLOCK" | "ROLLBACK" | "SKIP" | "ERROR"
        ip          : The IP address acted upon
        rule_id     : Unique ID of the iptables rule
        reason      : Human-readable reason (e.g., "risk_score >= 8")
        triggered_by: "auto_enforcer" | "manual_api" | "daemon"
        extra       : Any additional metadata dict
    """
    entry = {
        "log_id"      : str(uuid.uuid4()),
        "action"      : action,
        "ip"          : ip,
        "rule_id"     : rule_id,
        "reason"      : reason,
        "triggered_by": triggered_by,
        "timestamp"   : datetime.now(timezone.utc),
        "extra"       : extra or {}
    }
    audit_collection.insert_one(entry)
    print(f"[AUDIT] {action} | {ip} | {rule_id} | {reason}")
    return entry


def get_recent_logs(limit: int = 50):
    """Fetch recent audit log entries sorted by newest first."""
    return list(audit_collection.find().sort("timestamp", -1).limit(limit))


def get_logs_for_ip(ip: str):
    """Fetch all audit entries for a specific IP."""
    return list(audit_collection.find({"ip": ip}).sort("timestamp", -1))
