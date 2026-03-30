import os
import pymongo
import requests
import subprocess
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
                db.indicators.update_one({"_id": t["_id"]}, {"$set": {"status": "blocked"}})
        else:
            print(f"[-] {ip} failed VirusTotal verification. Skipping block.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run with sudo!")
    else:
        run_enforcement()
