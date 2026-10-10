# Règles Wazuh à surveiller
WATCHED_RULES = {
    "5763": "SSH brute force",
    "31106": "Web attack (SQLi)",
    # Regles Suricata : a ajouter une fois leur rule.id repere dans alerts.json
}

ALERTS_FILE = "data/alerts.json"