

# 🛡️ Threat Intelligence & Automated IPS Platform

## 📌 Project Overview

Financial institutions and enterprises face continuous cyber attacks from botnets, malware, and APTs. This platform addresses that by:

- **Collecting** malicious IP indicators from multiple OSINT sources
- **Storing** and scoring them in a MongoDB database
- **Automatically blocking** high-risk IPs at the firewall level via `iptables`
- **Alerting** SOC analysts when threats are detected or blocked
- **Allowing rollback** of any firewall rule in case of false positives
- **Visualizing** all threat data in a Kibana dashboard

---

## 🚀 Key Features

| Feature | Description |
|---|---|
| **OSINT Ingestion** | Fetches malicious IPs from AbuseIPDB and AlienVault OTX |
| **Risk Scoring** | Assigns risk scores (1–10) to every indicator |
| **VirusTotal Verification** | Double-checks each IP before blocking |
| **Auto Enforcement** | Python daemon that auto-adds `iptables DROP` rules |
| **Audit Trail** | Every block/unblock logged to MongoDB with `rule_id` |
| **SOC Rollback** | One-click unblock from dashboard or CLI |
| **Alerting Engine** | Stores alerts in DB + optional email notifications |
| **ELK Integration** | Exports data to Elasticsearch for Kibana visualization |
| **Real-time Dashboard** | Flask web UI with live stats, threat table, and alert panel |
| **Containerized** | MongoDB + Elasticsearch + Kibana via Docker Compose |

---

## 🏗️ Architecture

```
AlienVault OTX ──┐
AbuseIPDB ───────┤──► aggregator.py ──► MongoDB
                                            │
                                     enforcer.py (daemon)
                                            │
                             ┌──────────────┴──────────────┐
                        iptables DROP                 audit_log.py
                        (block IP)                  (MongoDB logs)
                                                          │
                                                  alert_engine.py
                                                  (DB + email alert)
                                                          │
                       app.py (Flask) ◄──── rollback.py ──┘
                       (Web Dashboard)    (remove iptables rule)
                             │
                    elk_exporter.py ──► Elasticsearch ──► Kibana
```

---

## 📁 Project Structure

```
Threat-Intel-Project/
│
├── aggregator.py        Week 1 — Fetches IPs from AbuseIPDB + AlienVault OTX
├── enforcer.py          Week 3 — Auto-blocks high-risk IPs via iptables
├── daemon_runner.py     Week 3 — Runs enforcer as a continuous background daemon
├── audit_log.py         Week 3 — Logs every block/rollback action to MongoDB
│
├── rollback.py          Week 4 — Reverses iptables rules (false positive handling)
├── alert_engine.py      Week 4 — Stores alerts in MongoDB + optional email alerts
├── elk_exporter.py      Week 4 — Pushes MongoDB data into Elasticsearch for Kibana
│
├── app.py               Flask dashboard with rollback API and alert routes
├── templates/
│   └── index.html       Web UI — threat table, unblock buttons, alerts panel
│
├── docker-compose.yml   MongoDB + Elasticsearch + Kibana
├── requirements.txt     Python dependencies
└── .env                 API keys (not committed to Git)
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Web Framework | Flask 3.1 |
| Database | MongoDB 7.0 (Docker) |
| Search & Analytics | Elasticsearch 8.13 + Kibana 8.13 |
| Firewall | Linux `iptables` |
| Threat Feeds | AbuseIPDB, AlienVault OTX, VirusTotal |
| Scheduler | Python `schedule` library |
| Environment | Kali Linux |

---

## 📋 Prerequisites

Before running, ensure you have:

- **Kali Linux** (or Ubuntu)
- **Python 3.10+**
- **Docker & Docker Compose** — `sudo apt install docker.io docker-compose`
- **sudo privileges** — required for `iptables` commands
- API Keys for:
  - [AbuseIPDB](https://www.abuseipdb.com/account/api) (free)
  - [AlienVault OTX](https://otx.alienvault.com/) (free)
  - [VirusTotal](https://www.virustotal.com/gui/my-apikey) (free)

---

## ⚙️ Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Svartak16/Threat-Intel-Project.git
cd Threat-Intel-Project
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

### 3. Create `.env` File

```bash
nano .env
```

Add the following and fill in your API keys:

```env
ABUSEIPDB_KEY=your_abuseipdb_key_here
OTX_API_KEY=your_alienvault_otx_key_here
VT_API_KEY=your_virustotal_key_here

# Email alerts (set to true to enable)
ALERT_EMAIL_ENABLED=false
ALERT_EMAIL_FROM=you@gmail.com
ALERT_EMAIL_TO=soc@yourorg.com
ALERT_SMTP_HOST=smtp.gmail.com
ALERT_SMTP_PORT=587
ALERT_SMTP_PASSWORD=your_app_password
```

### 4. Start Docker Services

```bash
docker-compose up -d
```

Verify all 3 containers are running:

```bash
docker ps
```

Expected — 3 containers active:
- `threat_db` → MongoDB on port 27017
- `tip_elasticsearch` → Elasticsearch on port 9200
- `tip_kibana` → Kibana on port 5601

---

## 🏃 Running the Platform

Open **4 terminal tabs** and run each in its own tab:

### Tab 1 — Fetch Threat Data

```bash
python3 aggregator.py
```

### Tab 2 — Start Web Dashboard

```bash
python3 app.py
```

Open browser → **http://localhost:5000**

### Tab 3 — Start Enforcement Daemon

```bash
# Single test cycle
sudo python3 daemon_runner.py --once

# Continuous mode (every 15 minutes)
sudo python3 daemon_runner.py

# Custom interval (every 5 minutes)
sudo python3 daemon_runner.py --interval 5
```

### Tab 4 — Export to Kibana

```bash
python3 elk_exporter.py
```

Open Kibana → **http://localhost:5601**

---

## 📊 Kibana Dashboard Setup (First Time Only)

1. Open **http://localhost:5601**
2. Click ☰ → **Stack Management** → **Index Patterns** → **Create index pattern**
3. Create these 3 index patterns:

| Pattern | Time Field |
|---|---|
| `tip-indicators-*` | `last_seen` |
| `tip-alerts` | `timestamp` |
| `tip-audit-logs` | `timestamp` |

4. Go to ☰ → **Discover** → select `tip-indicators-*` to explore your data

> Re-run `python3 elk_exporter.py` any time you want fresh data pushed to Kibana.

---

## 🔄 Rollback — Undoing a Firewall Block

**Via Dashboard:**
Click the **↩ UNBLOCK** button next to any blocked IP on the dashboard.

**Via CLI:**

```bash
# Roll back a specific IP
sudo python3 rollback.py --ip 1.2.3.4

# Roll back by rule ID
sudo python3 rollback.py --rule-id RULE-20240407-ABC123

# Roll back ALL active blocks
sudo python3 rollback.py --all
```

---

## 🔍 Verification Commands

```bash
# Check MongoDB has data
python3 -c "import pymongo; db=pymongo.MongoClient()['threat_intel']; print('Indicators:', db.indicators.count_documents({}))"

# View active iptables blocks
sudo iptables -L INPUT -n --line-numbers

# Check Elasticsearch is up
curl http://localhost:9200

# Check Kibana is up
curl http://localhost:5601/api/status
```

---

## 🗄️ MongoDB Collections

| Collection | Purpose |
|---|---|
| `indicators` | Threat IP records — risk scores, block status, rule_id |
| `audit_logs` | Every enforcement and rollback action with timestamps |
| `alerts` | Security alerts shown on dashboard and sent via email |

---

## ⚠️ Troubleshooting

| Error | Fix |
|---|---|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt --break-system-packages` |
| `docker: command not found` | Run `sudo apt install docker.io docker-compose` |
| `Connection refused` on MongoDB | Run `docker-compose up -d` first |
| `Run with sudo!` on enforcer | Use `sudo python3 daemon_runner.py` |
| `TemplateNotFound: index.html` | Ensure `index.html` is inside the `templates/` folder |
| Kibana blank or loading forever | Wait 60–90 seconds after `docker-compose up -d` |
| Elasticsearch connection error | Run `curl http://localhost:9200` to verify it's up |

---

## 📅 Development Timeline

| Week | Deliverable | Key Files |
|---|---|---|
| Week 1 | OSINT Ingestion & MongoDB Setup | `aggregator.py` |
| Week 2 | Risk Scoring & SIEM Integration | `app.py`, `docker-compose.yml` |
| Week 3 | Dynamic Policy Enforcement Engine | `enforcer.py`, `daemon_runner.py`, `audit_log.py` |
| Week 4 | Rollback, Alerting & Kibana Dashboard | `rollback.py`, `alert_engine.py`, `elk_exporter.py` |

---

## 🔐 Security Notes

- Never commit your `.env` file to GitHub — add it to `.gitignore`
- `xpack.security` is disabled in Docker for local lab use — enable it for production
- `iptables` rules are not persistent across reboots — use `iptables-save` for persistence

---

## 📄 License

This project was developed as part of a cybersecurity internship program focused on Threat Intelligence and Automated IPS systems.
