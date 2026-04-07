"""
alert_engine.py - Week 4
Alerting system for the TIP platform.
- Writes alerts to MongoDB 'alerts' collection (always)
- Optionally sends email via SMTP (configure in .env)
- Called by enforcer.py and rollback.py after major actions

Environment variables (.env):
    ALERT_EMAIL_FROM     = sender@example.com
    ALERT_EMAIL_TO       = soc@yourbank.com
    ALERT_SMTP_HOST      = smtp.gmail.com
    ALERT_SMTP_PORT      = 587
    ALERT_SMTP_PASSWORD  = your_app_password
    ALERT_EMAIL_ENABLED  = true   (set false to disable email, still logs to DB)
"""

import os
import smtplib
import pymongo
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
alerts_col = db["alerts"]

# Email config from .env
EMAIL_ENABLED  = os.getenv("ALERT_EMAIL_ENABLED", "false").lower() == "true"
EMAIL_FROM     = os.getenv("ALERT_EMAIL_FROM", "")
EMAIL_TO       = os.getenv("ALERT_EMAIL_TO", "")
SMTP_HOST      = os.getenv("ALERT_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT      = int(os.getenv("ALERT_SMTP_PORT", 587))
SMTP_PASSWORD  = os.getenv("ALERT_SMTP_PASSWORD", "")


# ─────────────────────────────────────────────
# Store Alert in MongoDB
# ─────────────────────────────────────────────
def _store_alert(alert_type: str, ip: str, rule_id: str, message: str, severity: str) -> str:
    doc = {
        "alert_type": alert_type,       # "BLOCK_TRIGGERED" | "ROLLBACK_PERFORMED" | "HIGH_RISK_DETECTED"
        "ip"        : ip,
        "rule_id"   : rule_id,
        "message"   : message,
        "severity"  : severity,         # "HIGH" | "MEDIUM" | "INFO"
        "timestamp" : datetime.now(timezone.utc),
        "read"      : False
    }
    result = alerts_col.insert_one(doc)
    return str(result.inserted_id)


# ─────────────────────────────────────────────
# Send Email
# ─────────────────────────────────────────────
def _send_email(subject: str, body: str):
    if not EMAIL_ENABLED:
        return
    if not all([EMAIL_FROM, EMAIL_TO, SMTP_PASSWORD]):
        print("[ALERT] Email not configured — skipping email send.")
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[TIP ALERT] {subject}"
        msg["From"]    = EMAIL_FROM
        msg["To"]      = EMAIL_TO
        html_body = f"""
        <html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px;">
            <h2 style="color:#f85149;">⚠️ TIP Security Alert</h2>
            <hr style="border-color:#30363d;">
            <pre style="color:#58a6ff;">{body}</pre>
            <hr style="border-color:#30363d;">
            <p style="color:#8b949e;font-size:12px;">Threat Intelligence Platform — Automated Alert</p>
        </body></html>
        """
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        print(f"[ALERT] Email sent to {EMAIL_TO}")
    except Exception as e:
        print(f"[ALERT EMAIL ERROR] {e}")


# ─────────────────────────────────────────────
# Public Alert Functions
# ─────────────────────────────────────────────
def alert_block_triggered(ip: str, rule_id: str, risk_score: float, source: str):
    """Fire when enforcer auto-blocks an IP."""
    subject = f"Auto-Block Triggered: {ip}"
    body = (
        f"ACTION   : AUTO-BLOCK\n"
        f"IP       : {ip}\n"
        f"RULE_ID  : {rule_id}\n"
        f"SCORE    : {risk_score}/10\n"
        f"SOURCE   : {source}\n"
        f"TIME     : {datetime.now(timezone.utc).isoformat()}\n"
        f"\nA DROP rule has been added to iptables.\n"
        f"Use the dashboard to review and rollback if this is a false positive."
    )
    _store_alert("BLOCK_TRIGGERED", ip, rule_id, body, "HIGH")
    _send_email(subject, body)
    print(f"[ALERT] Block alert stored for {ip}")


def alert_rollback_performed(ip: str, rule_id: str, triggered_by: str):
    """Fire when a block is rolled back."""
    subject = f"Block Rolled Back: {ip}"
    body = (
        f"ACTION      : ROLLBACK\n"
        f"IP          : {ip}\n"
        f"RULE_ID     : {rule_id}\n"
        f"TRIGGERED_BY: {triggered_by}\n"
        f"TIME        : {datetime.now(timezone.utc).isoformat()}\n"
        f"\nThe DROP rule has been removed from iptables."
    )
    _store_alert("ROLLBACK_PERFORMED", ip, rule_id, body, "MEDIUM")
    _send_email(subject, body)
    print(f"[ALERT] Rollback alert stored for {ip}")


def alert_high_risk_detected(ip: str, risk_score: float, source: str):
    """Fire when a new high-risk indicator enters the database (pre-block)."""
    subject = f"High-Risk Indicator Detected: {ip}"
    body = (
        f"ACTION  : HIGH_RISK_DETECTED\n"
        f"IP      : {ip}\n"
        f"SCORE   : {risk_score}/10\n"
        f"SOURCE  : {source}\n"
        f"TIME    : {datetime.now(timezone.utc).isoformat()}\n"
        f"\nThis IP will be reviewed by the enforcer daemon in the next cycle."
    )
    _store_alert("HIGH_RISK_DETECTED", ip, "PENDING", body, "MEDIUM")
    print(f"[ALERT] High-risk detection alert stored for {ip}")


def get_unread_alerts(limit: int = 20):
    """Return unread alerts sorted newest first."""
    return list(alerts_col.find({"read": False}).sort("timestamp", -1).limit(limit))


def get_all_alerts(limit: int = 50):
    """Return all alerts sorted newest first."""
    return list(alerts_col.find().sort("timestamp", -1).limit(limit))


def mark_alert_read(alert_id: str):
    """Mark a specific alert as read by its MongoDB _id string."""
    from bson import ObjectId
    alerts_col.update_one({"_id": ObjectId(alert_id)}, {"$set": {"read": True}})
