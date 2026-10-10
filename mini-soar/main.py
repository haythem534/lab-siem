import os
from config import ALERTS_FILE
from soar.ingest import load_alerts
from soar.enrich import enrich

# Mode démo : remplace les IP privées par une IP publique connue pour avoir
# un résultat visible. Mets ici une IP récemment signalée sur AbuseIPDB.
DEMO_IP = os.environ.get("DEMO_IP")

def dedupe(alerts):
    seen = {}
    for a in alerts:
        key = (a["rule_id"], a["src_ip"])
        if key in seen:
            seen[key]["count"] += 1
        else:
            seen[key] = dict(a, count=1)
    return list(seen.values())

if __name__ == "__main__":
    alerts = load_alerts(ALERTS_FILE)
    enriched = [enrich(a, DEMO_IP) for a in alerts]
    enriched.sort(key=lambda a: a["score"], reverse=True)
    from soar.notify import send_discord
    for a in enriched:
        if a["score"] >= 40:
            send_discord(a)

    for a in enriched:
        tag = " [DEMO]" if a["demo"] else ""
        print(f'{a["label"]:9} {a["score"]:3}  règle {a["rule_id"]}  {a["src_ip"]}{tag}')
        print(f'          MITRE: {", ".join(a["mitre_names"])}')
        if a["ip_public"]:
            print(f'          AbuseIPDB: {a.get("abuse_score")}% ({a.get("abuse_reports")} signalements, {a.get("country")})')
            print(f'          VirusTotal: {a.get("vt_malicious")} malveillant(s), {a.get("vt_suspicious")} suspect(s)')
        else:
            print('          Réputation: IP privée, non interrogée')
        if "enrich_error" in a:
            print(f'          ERREUR enrichissement: {a["enrich_error"]}')
        print(f'          Action: {a["action"]}')