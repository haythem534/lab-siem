import os
import requests

COLORS = {"CRITIQUE": 0xE74C3C, "MOYEN": 0xF39C12, "FAIBLE": 0x2ECC71}

def send_discord(alert):
    url = os.environ["DISCORD_WEBHOOK"].strip()
    demo = " [DEMO]" if alert.get("demo") else ""
    fields = [
        {"name": "IP source", "value": f'`{alert["src_ip"]}`{demo}', "inline": True},
        {"name": "Règle", "value": f'{alert["rule_id"]} (niveau {alert["level"]})', "inline": True},
        {"name": "Score", "value": f'{alert["score"]}/100', "inline": True},
        {"name": "MITRE ATT&CK", "value": ", ".join(alert["mitre_names"]) or "n/a"},
    ]
    if alert.get("ip_public"):
        fields.append({
            "name": "Réputation",
            "value": f'AbuseIPDB {alert.get("abuse_score")}% · VirusTotal {alert.get("vt_malicious")} malveillant(s)',
        })
    fields.append({"name": "Action recommandée", "value": alert["action"]})

    payload = {"embeds": [{
        "title": f'{alert["label"]} · {alert["description"]}',
        "color": COLORS[alert["label"]],
        "fields": fields,
        "timestamp": alert["timestamp"].replace("+0000", "+00:00"),
    }]}
    r = requests.post(url, json=payload, timeout=10)
    r.raise_for_status()