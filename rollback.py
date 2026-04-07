"""
rollback.py - Week 4
SOC Analyst Rollback Mechanism.
Allows reversal of any automated firewall block by rule_id or IP.

Usage (CLI):
    sudo python3 rollback.py --ip 1.2.3.4
    sudo python3 rollback.py --rule-id TIP-20240407120000-ABCD1234
    sudo python3 rollback.py --all          # Roll back ALL active blocks (use with caution)
"""

import os
import sys
import argparse
import subprocess
import pymongo
from datetime import datetime, timezone
from audit_log import log_action

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]


# ─────────────────────────────────────────────
# Core Rollback Function
# ─────────────────────────────────────────────
def rollback_ip(ip: str, rule_id: str, triggered_by: str = "manual_api") -> dict:
    """
    Remove the iptables DROP rule for a given IP using its embedded comment (rule_id).
    Updates MongoDB and writes an audit log entry.

    Returns:
        dict with keys: success (bool), message (str)
    """
    print(f"[ROLLBACK] Attempting rollback for IP={ip}, rule_id={rule_id}")

    # 1. Remove the iptables rule (match by comment = rule_id)
    try:
        cmd = [
            "sudo", "iptables",
            "-D", "INPUT",
            "-s", ip,
            "-m", "comment", "--comment", rule_id,
            "-j", "DROP"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            # Rule may already be gone — still update DB
            print(f"  [WARN] iptables removal returned non-zero: {result.stderr.strip()}")
        else:
            print(f"  [FIREWALL] Removed DROP rule for {ip}")

    except Exception as e:
        print(f"  [ERROR] Failed to run iptables: {e}")
        return {"success": False, "message": str(e)}

    # 2. Update MongoDB document
    db.indicators.update_one(
        {"indicator": ip},
        {"$set": {
            "status"         : "rolled_back",
            "rollback_status": "rolled_back",
            "rolled_back_at" : datetime.now(timezone.utc),
            "rollback_by"    : triggered_by
        }}
    )

    # 3. Write audit log
    log_action(
        action="ROLLBACK",
        ip=ip,
        rule_id=rule_id,
        reason="SOC analyst initiated rollback (false positive review)",
        triggered_by=triggered_by,
        extra={"rolled_back_at": datetime.now(timezone.utc).isoformat()}
    )

    msg = f"Successfully rolled back block for {ip} (rule_id={rule_id})"
    print(f"  [OK] {msg}")
    return {"success": True, "message": msg}


def rollback_by_ip(ip: str, triggered_by: str = "manual_cli") -> dict:
    """Look up the rule_id from MongoDB then rollback."""
    doc = db.indicators.find_one({"indicator": ip, "status": "blocked"})
    if not doc:
        return {"success": False, "message": f"No active block found for IP: {ip}"}
    rule_id = doc.get("rule_id", "UNKNOWN")
    return rollback_ip(ip, rule_id, triggered_by)


def rollback_by_rule_id(rule_id: str, triggered_by: str = "manual_cli") -> dict:
    """Look up IP from MongoDB by rule_id then rollback."""
    doc = db.indicators.find_one({"rule_id": rule_id, "status": "blocked"})
    if not doc:
        return {"success": False, "message": f"No active block found for rule_id: {rule_id}"}
    ip = doc["indicator"]
    return rollback_ip(ip, rule_id, triggered_by)


def rollback_all(triggered_by: str = "manual_cli") -> list:
    """Roll back ALL active blocks. Returns list of result dicts."""
    blocked = list(db.indicators.find({"status": "blocked"}))
    print(f"[ROLLBACK] Rolling back {len(blocked)} active blocks...")
    results = []
    for doc in blocked:
        ip      = doc["indicator"]
        rule_id = doc.get("rule_id", "UNKNOWN")
        res = rollback_ip(ip, rule_id, triggered_by)
        results.append({**res, "ip": ip})
    return results


# ─────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] rollback.py requires sudo for iptables access.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="TIP Rollback — Undo firewall blocks")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip",      type=str, help="Roll back block for a specific IP")
    group.add_argument("--rule-id", type=str, help="Roll back by rule_id")
    group.add_argument("--all",     action="store_true", help="Roll back ALL active blocks")
    args = parser.parse_args()

    if args.ip:
        result = rollback_by_ip(args.ip)
        print(result["message"])
    elif args.rule_id:
        result = rollback_by_rule_id(args.rule_id)
        print(result["message"])
    elif args.all:
        results = rollback_all()
        success = sum(1 for r in results if r["success"])
        print(f"\n[ROLLBACK] Done. {success}/{len(results)} rules removed.")
