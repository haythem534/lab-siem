import json
from config import WATCHED_RULES

def load_alerts(path):
    """Lit alerts.json (1 JSON par ligne) et garde les regles surveillées."""
    alerts = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue  # ligne tronquée
            rule_id = a.get("rule", {}).get("id")
            if rule_id in WATCHED_RULES:
                alerts.append(normalize(a))
    return alerts

def normalize(a):
    """Ne garde que les champs utiles, dans un format simple."""
    return {
        "timestamp": a.get("timestamp"),
        "rule_id": a["rule"]["id"],
        "description": a["rule"].get("description"),
        "level": a["rule"].get("level"),
        "mitre": a["rule"].get("mitre", {}).get("id", []),
        "src_ip": a.get("data", {}).get("srcip"),
        "agent": a.get("agent", {}).get("name"),
    }