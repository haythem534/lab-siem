import os
import time
import ipaddress
from functools import lru_cache

import requests

MITRE_NAMES = {
    "T1190": "Exploit Public-Facing Application",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1046": "Network Service Discovery",
}

ACTIONS = {
    "5763": "Bloquer l'IP source (pare-feu / fail2ban), vérifier si un login a réussi ensuite",
    "31106": "Examiner les logs web, vérifier l'intégrité de la base, mettre en place un WAF",
    "31103": "Examiner les logs web, vérifier l'intégrité de la base, mettre en place un WAF",
}

def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

@lru_cache(maxsize=None)
def abuseipdb(ip):
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": os.environ["ABUSEIPDB_KEY"], "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=10,
    )
    r.raise_for_status()
    d = r.json()["data"]
    return {
        "abuse_score": d["abuseConfidenceScore"],
        "abuse_reports": d["totalReports"],
        "country": d.get("countryCode"),
    }

@lru_cache(maxsize=None)
def virustotal(ip):
    r = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": os.environ["VT_KEY"]},
        timeout=10,
    )
    r.raise_for_status()
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    time.sleep(15)
    return {
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
    }

def severity(alert):
    score = alert["level"] * 5
    score += alert.get("abuse_score", 0) * 0.4
    score += min(alert.get("vt_malicious", 0), 10) * 3
    score = min(int(score), 100)
    if score >= 70:
        label = "CRITIQUE"
    elif score >= 40:
        label = "MOYEN"
    else:
        label = "FAIBLE"
    return score, label

def enrich(alert, demo_ip=None):
    a = dict(alert)
    lookup_ip = demo_ip or a["src_ip"]
    a["demo"] = bool(demo_ip)
    a["ip_public"] = bool(lookup_ip) and is_public(lookup_ip)

    if a["ip_public"]:
        errors = []
        try:
            a.update(abuseipdb(lookup_ip))
        except (requests.RequestException, KeyError) as e:
            errors.append(f"AbuseIPDB: {e}")
        try:
            a.update(virustotal(lookup_ip))
        except (requests.RequestException, KeyError) as e:
            errors.append(f"VirusTotal: {e}")
        if errors:
            a["enrich_error"] = " | ".join(errors)

    a["mitre_names"] = [MITRE_NAMES.get(t, t) for t in a["mitre"]]
    a["action"] = ACTIONS.get(a["rule_id"], "Investigation manuelle")
    a["score"], a["label"] = severity(a)
    return a
