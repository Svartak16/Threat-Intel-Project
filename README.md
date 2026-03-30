🛡️ Threat Intelligence & Automated IPS Platform
A professional-grade Threat Intelligence Platform built for Kali Linux. This system aggregates malicious IP data from global threat feeds, stores them in a NoSQL database, and automatically enforces network security by blocking high-risk IPs using the Linux Kernel Firewall (iptables).

🚀 Key Features
Data Aggregation: Automatically fetches 10,000+ malicious indicators from public threat APIs.

Automated Enforcement: Python-based "Enforcer" script that dynamically adds DROP rules to the Linux Firewall.

Real-time Dashboard: Flask-based web interface to monitor active blocks and risk scores.

Containerized Database: Uses Docker & MongoDB for scalable, high-performance threat storage.

Security Analytics: Categorizes threats by type (Botnet, Malware, Phishing) and assigns risk levels.

🛠️ Tech Stack
Language: Python 3.10+

Framework: Flask (Web UI)

Database: MongoDB (via Docker)

Security: Linux iptables (Packet Filtering)

Environment: Kali Linux / Ubuntu

📋 Prerequisites
Before running, ensure you have the following installed:

Docker & Docker-Compose

Python 3.10+

sudo privileges (required for Firewall modification)

⚙️ Installation & Setup
1. Clone the Repository
Bash
git clone https://github.com/Svartak16/Threat-Intel-Project.git
cd Threat-Intel-Project
2. Setup Virtual Environment
Bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
3. Launch Database
Bash
sudo docker-compose up -d
🏃 Execution Flow
Step 1: Collect Threat Data
Run the aggregator to pull the latest malicious IPs into your database:

Bash
python3 aggregator.py
Step 2: Enable Firewall Enforcement
Block high-risk IPs in the system firewall:

Bash
sudo ./venv/bin/python enforcer.py
Step 3: Launch Monitoring Dashboard
Bash
python3 app.py
View the results at: http://localhost:5000

🔍 Verification
To see the active blocks in your Linux Kernel, run:

Bash
sudo iptables -L INPUT -n --line-numbers
