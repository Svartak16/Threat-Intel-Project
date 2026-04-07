import os
import pymongo
import requests
import subprocess
import time
import uuid
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
VT_KEY = os.getenv("VT_API_KEY")
db = pymongo.MongoClient("mongodb://localhost:27017/")["threat_intel"]

def check_virustotal(ip):
    """Verify IP with VirusTotal v3 API"""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_KEY}
    try:
        res = requests.get(url, headers=headers)
        stats = res.json()['data']['attributes']['last_analysis_stats']
        # If more than 5 security vendors flag it, it's definitely malicious
        return stats['malicious'] > 5
    except:
        return False

def block_in_kali(ip):
    try:
        check_cmd = ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
        if subprocess.run(check_cmd, capture_output=True).returncode != 0:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"[FIREWALL] Blocked malicious IP: {ip}")
        return True
    except:
        return False

def run_enforcement():
    # Target high-risk active threats
    threats = db.indicators.find({"risk_score": {"$gte": 8}, "status": "active"})
    for t in threats:
        ip = t['indicator']
        print(f"[*] Analyzing {ip}...")
        
        # Double-check with VirusTotal
        if check_virustotal(ip):
            if block_in_kali(ip):
                 new_rule_id = f"RULE-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
                
                 db.indicators.update_one(
                    {"_id": t["_id"]}, 
                    {"$set": {
                        "status": "blocked",
                        "rule_id": new_rule_id,
                        "blocked_at": datetime.utcnow(),
                        "block_reason": "auto_enforcer",
                        "rollback_status": "active"
                    }}
                )
            print(f"[DB] Updated Audit Trail for {ip}")
        else:
            print(f"[-] {ip} failed VT verification. Skipping.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run with sudo!")
    else:
        print("--- Enforcer Daemon Active ---")
        try:
            while True:
                run_enforcement()
                time.sleep(300) # Runs every 5 minutes
        except KeyboardInterrupt:
            print("\n[!] Daemon stopped by user.")