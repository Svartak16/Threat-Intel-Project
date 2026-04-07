"""
elk_exporter.py - Week 4
Pushes MongoDB threat indicators into Elasticsearch for Kibana visualization.

Usage:
    python3 elk_exporter.py              # Full export
    python3 elk_exporter.py --since 1h   # Only export indicators updated in last 1 hour
    python3 elk_exporter.py --since 24h  # Last 24 hours

Kibana will auto-discover the 'tip-indicators' index.
Create an index pattern in Kibana: tip-indicators-*
"""

import sys
import argparse
import pymongo
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch, helpers

# ─────────────────────────────────────────────
# Connections
# ─────────────────────────────────────────────
mongo_client = pymongo.MongoClient("mongodb://localhost:27017/")
db = mongo_client["threat_intel"]

es = Elasticsearch("http://localhost:9200")

INDEX_PREFIX = "tip-indicators"
ALERTS_INDEX = "tip-alerts"
AUDIT_INDEX  = "tip-audit-logs"


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def _get_index_name():
    """Date-stamped index name e.g. tip-indicators-2024.04.07"""
    return f"{INDEX_PREFIX}-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"


def _mongo_doc_to_es(doc: dict, index: str) -> dict:
    """Convert a MongoDB document to an Elasticsearch bulk action."""
    doc_id = str(doc.pop("_id"))  # use Mongo _id as ES doc id
    # Convert datetime objects to ISO strings
    for key, val in doc.items():
        if isinstance(val, datetime):
            doc[key] = val.isoformat()
    return {
        "_index": index,
        "_id"   : doc_id,
        "_source": doc
    }


# ─────────────────────────────────────────────
# Export Indicators
# ─────────────────────────────────────────────
def export_indicators(since_hours: int = None):
    """Export threat indicators from MongoDB to Elasticsearch."""
    index = _get_index_name()
    query = {}
    if since_hours:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        query = {"last_seen": {"$gte": cutoff}}

    docs = list(db.indicators.find(query))
    if not docs:
        print("[ELK] No indicators to export.")
        return 0

    actions = [_mongo_doc_to_es(doc, index) for doc in docs]
    success, failed = helpers.bulk(es, actions, raise_on_error=False)
    print(f"[ELK] Indicators — Exported: {success}, Failed: {len(failed)}")
    return success


# ─────────────────────────────────────────────
# Export Alerts
# ─────────────────────────────────────────────
def export_alerts(since_hours: int = None):
    """Export alerts collection to Elasticsearch."""
    query = {}
    if since_hours:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        query = {"timestamp": {"$gte": cutoff}}

    docs = list(db.alerts.find(query))
    if not docs:
        print("[ELK] No alerts to export.")
        return 0

    actions = [_mongo_doc_to_es(doc, ALERTS_INDEX) for doc in docs]
    success, failed = helpers.bulk(es, actions, raise_on_error=False)
    print(f"[ELK] Alerts — Exported: {success}, Failed: {len(failed)}")
    return success


# ─────────────────────────────────────────────
# Export Audit Logs
# ─────────────────────────────────────────────
def export_audit_logs(since_hours: int = None):
    """Export audit_logs collection to Elasticsearch."""
    query = {}
    if since_hours:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        query = {"timestamp": {"$gte": cutoff}}

    docs = list(db.audit_logs.find(query))
    if not docs:
        print("[ELK] No audit logs to export.")
        return 0

    actions = [_mongo_doc_to_es(doc, AUDIT_INDEX) for doc in docs]
    success, failed = helpers.bulk(es, actions, raise_on_error=False)
    print(f"[ELK] Audit Logs — Exported: {success}, Failed: {len(failed)}")
    return success


# ─────────────────────────────────────────────
# Check Elasticsearch Connection
# ─────────────────────────────────────────────
def check_es_connection():
    try:
        info = es.info()
        print(f"[ELK] Connected to Elasticsearch v{info['version']['number']}")
        return True
    except Exception as e:
        print(f"[ELK ERROR] Cannot connect to Elasticsearch: {e}")
        print("  Make sure Elasticsearch is running:")
        print("  docker-compose up -d elasticsearch")
        return False


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TIP → Elasticsearch Exporter")
    parser.add_argument("--since", type=str, default=None,
                        help="Only export data updated in last N hours (e.g. 1h, 24h, 168h)")
    args = parser.parse_args()

    since_hours = None
    if args.since:
        since_hours = int(args.since.replace("h", "").replace("H", ""))

    if not check_es_connection():
        sys.exit(1)

    print(f"\n[ELK] Starting export{f' (last {since_hours}h)' if since_hours else ' (full)'}...")
    total  = export_indicators(since_hours)
    total += export_alerts(since_hours)
    total += export_audit_logs(since_hours)
    print(f"\n[ELK] Export complete. Total documents sent: {total}")
    print(f"[ELK] Open Kibana at http://localhost:5601")
    print(f"[ELK] Create index patterns: tip-indicators-*, tip-alerts, tip-audit-logs")
