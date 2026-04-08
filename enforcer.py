import os
import pymongo
import requests
import subprocess
import time
import uuid
from datetime import datetime, timezone
from dotenv import load_dotenv
from audit_log import log_action
from alert_engine import alert_block_triggered

load_dotenv()
VT_KEY = os.getenv("VT_API_KEY")
db = pymongo.MongoClient("mongodb://localhost:27017/")["threat_intel"]

def check_virustotal(ip):
    """Verify IP with VirusTotal v3 API"""
    if not VT_KEY:
        print("  [WARN] No VT_API_KEY set — skipping VirusTotal check.")
        return True
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_KEY}
    try:
        res = requests.get(url, headers=headers, timeout=10)
        stats = res.json()["data"]["attributes"]["last_analysis_stats"]
        flagged = stats.get("malicious", 0)
        print(f"  [VT] {ip} flagged by {flagged} vendors.")
        return flagged > 5
    except Exception as e:
        print(f"  [VT ERROR] {ip}: {e}")
        return False

def block_in_kali(ip, rule_id):
    try:
        check_cmd = ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
        if subprocess.run(check_cmd, capture_output=True).returncode == 0:
            print(f"  [FIREWALL] Rule already exists for {ip}, skipping.")
            return True

        cmd = [
            "sudo", "iptables",
            "-A", "INPUT",
            "-s", ip,
            "-m", "comment", "--comment", rule_id,
            "-j", "DROP"
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"  [FIREWALL] Blocked {ip}  (rule_id={rule_id})")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  [FIREWALL ERROR] Could not block {ip}: {e.stderr.decode()}")
        return False

def run_enforcement():
    print(f"\n[ENFORCER] Cycle started — {datetime.now(timezone.utc).isoformat()}")

    threats = list(db.indicators.find({"risk_score": {"$gte": 8}, "status": "active"}))
    print(f"[ENFORCER] Found {len(threats)} high-risk active indicators.")

    blocked_count = 0
    skipped_count = 0

    for threat in threats:
        ip      = threat["indicator"]
        score   = threat.get("risk_score", 0)
        source  = threat.get("source", "unknown")
        rule_id = f"RULE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

        print(f"\n[*] Analyzing {ip}  (score={score}, source={source})")

        if not check_virustotal(ip):
            print(f"  [-] {ip} did NOT pass VirusTotal check. Skipping.")
            log_action(
                action="SKIP",
                ip=ip,
                rule_id="N/A",
                reason=f"VirusTotal check failed (score={score})",
                triggered_by="auto_enforcer"
            )
            skipped_count += 1
            continue

        if block_in_kali(ip, rule_id):
            db.indicators.update_one(
                {"_id": threat["_id"]},
                {"$set": {
                    "status":          "blocked",
                    "rule_id":         rule_id,
                    "blocked_at":      datetime.now(timezone.utc),
                    "block_reason":    "auto_enforcer",
                    "rollback_status": "active"
                }}
            )
            log_action(
                action="BLOCK",
                ip=ip,
                rule_id=rule_id,
                reason=f"risk_score={score} >= 8, VT confirmed",
                triggered_by="auto_enforcer",
                extra={"source": source, "score": score}
            )
            alert_block_triggered(ip, rule_id, score, source)
            blocked_count += 1
        else:
            log_action(
                action="ERROR",
                ip=ip,
                rule_id=rule_id,
                reason="iptables command failed",
                triggered_by="auto_enforcer"
            )

    print(f"\n[ENFORCER] Cycle complete. Blocked={blocked_count}, Skipped={skipped_count}")
    return blocked_count


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] enforcer.py must be run with sudo for iptables access.")
        print("    Usage: sudo python3 enforcer.py")
    else:
        print("--- Enforcer Daemon Active ---")
        try:
            while True:
                run_enforcement()
                time.sleep(300)
        except KeyboardInterrupt:
            print("\n[!] Daemon stopped by user.")
