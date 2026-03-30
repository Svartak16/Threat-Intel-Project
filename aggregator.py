import os
import requests
import pymongo
from dotenv import load_dotenv
from datetime import datetime
from datetime import datetime, timezone
# Load keys from .env
load_dotenv()
ABUSE_KEY = os.getenv("ABUSEIPDB_KEY")
OTX_KEY = os.getenv("OTX_API_KEY")

# DB Connection
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
collection = db["indicators"]

def fetch_abuse_ipdb():
    print("[*] Fetching from AbuseIPDB...")
    url = 'https://api.abuseipdb.com/api/v2/blacklist'
    headers = {'Accept': 'application/json', 'Key': ABUSE_KEY}
    params = {'confidenceMinimum': '75'} # Only high-confidence threats
    
    try:
        res = requests.get(url, headers=headers, params=params)
        data = res.json().get('data', [])
        for item in data:
            collection.update_one(
                {"indicator": item['ipAddress']},
                {"$set": {
                    "indicator": item['ipAddress'],
                    "risk_score": item['abuseConfidenceScore'] / 10, # Scale to 1-10
                    "source": "AbuseIPDB",
                    "status": "active",
                    "last_seen": datetime.now(timezone.utc)
                }}, upsert=True
            )
        print(f"[+] Loaded {len(data)} IPs from AbuseIPDB.")
    except Exception as e:
        print(f"[!] AbuseIPDB Error: {e}")

def fetch_otx_pulses():
    print("[*] Fetching from AlienVault OTX...")
    # Getting the most recent general pulses
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    
    try:
        res = requests.get(url, headers=headers)
        pulses = res.json().get('results', [])
        count = 0
        for pulse in pulses[:5]: # Check first 5 pulses
            for ioc in pulse.get('indicators', []):
                if ioc['type'] == 'IPv4' and count < 50:
                    collection.update_one(
                        {"indicator": ioc['indicator']},
                        {"$set": {
                            "indicator": ioc['indicator'],
                            "risk_score": 7, # OTX pulses are generally high risk
                            "source": "AlienVault",
                            "status": "active",
                            "last_seen": datetime.now(timezone.utc)
                        }}, upsert=True
                    )
                    count += 1
        print(f"[+] Loaded {count} IPs from AlienVault.")
    except Exception as e:
        print(f"[!] OTX Error: {e}")

if __name__ == "__main__":
    fetch_abuse_ipdb()
    fetch_otx_pulses()
