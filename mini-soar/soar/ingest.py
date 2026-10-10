import json
from config import WATCHED_RULES

def load_alerts(path):
    alerts = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue
            rule_id = a.get("rule", {}).get("id")
            if rule_id in WATCHED_RULES:
                alerts.append(normalize(a))
    return alerts

def normalize(a):
    return {
        "timestamp": a.get("timestamp"),
        "rule_id": a["rule"]["id"],
        "description": a["rule"].get("description"),
        "level": a["rule"].get("level"),
        "mitre": a["rule"].get("mitre", {}).get("id", []),
        "src_ip": a.get("data", {}).get("srcip"),
        "agent": a.get("agent", {}).get("name"),
    }
