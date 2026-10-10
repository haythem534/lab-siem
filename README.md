# Intrusion Detection Lab with SIEM — Suricata + Wazuh

## Objective

Build a small virtualized environment to monitor a network with **Suricata** (network-based detection) and **Wazuh** (SIEM, host-based detection, correlation and active response), then carry out several real attacks against that network and document precisely how each one was detected.

The goal isn't just to show that detection works "out of the box," but to understand its limits (what isn't detected by default) and address them with custom rules and automated response.

## Architecture

4 virtual machines under VirtualBox, connected through an isolated *host-only* internal network (`192.168.56.0/24`), each also given a NAT adapter for internet access (updates only).

| Machine | OS | RAM | vCPU | IP (host-only) | Role |
|---|---|---|---|---|---|
| Wazuh | OVA appliance | 4 GB | 4 | 192.168.56.102 | Manager, indexer, dashboard |
| Target | Ubuntu Server 24.04 LTS | 2 GB | 2 | 192.168.56.20 | Wazuh agent, Suricata, Apache, SSH, DVWA |
| Attacker | Kali Linux (headless) | 1 GB | 2 | 192.168.56.30 | Attack tools (Nmap, Hydra, etc...) |
| Host PC | — | — | — | 192.168.56.1 | Browser used to reach the dashboard and DVWA |

*(Detailed network diagram: see `network-diagram.png`)*

**Hardware constraint**: the whole lab was designed to run on a host machine with 16 GB of RAM (i5-12400F), hence the deliberately limited resources allocated to each VM.

## Setup

1. Deployed the 4 VMs under VirtualBox, configured host-only + NAT networking.
2. Installed the official Wazuh OVA appliance.
3. Installed Ubuntu Server 24.04 LTS as the target, with:
   - Wazuh agent (official APT repository, registered with the manager)
   - Suricata (Emerging Threats ruleset + custom rules)
   - Apache, MariaDB, PHP + DVWA (Damn Vulnerable Web Application)
4. Log integration: `eve.json` (Suricata) and `access.log` (Apache) forwarded to Wazuh through the agent (`ossec.conf` → `<localfile>`).
5. Installed Kali Linux in terminal-only mode (no GUI) as the attacking machine.

## Attacks performed and detection

| # | Attack | Command | Detection | Source | Rule ID / SID | MITRE ATT&CK |
|---|---|---|---|---|---|---|
| 1 | Port scan | `nmap -sS -p 1-1000 <target>` | Suricata (custom rule) | `eve.json` → Wazuh dashboard | sid **1000003** | T1046 — Network Service Discovery |
| 1b | Service-detection scan | `nmap -sV -A <target>` | Suricata (default Emerging Threats rule) | `eve.json` → Wazuh dashboard | signature_id **2024364** | T1046 |
| 2 | SSH brute force | `hydra -l victime -P mdp.txt ssh://<target>` | Wazuh (authentication log analysis) | journald/auth.log | rule.id **5763** | T1110 — Brute Force |
| 2b | SSH brute force (network layer) | same | Suricata (custom rule, connection-rate threshold) | `eve.json` → Wazuh dashboard | sid **1000004** | T1110 |
| 2c | Automated response | triggered after 8 failures within 2 minutes | Wazuh Active Response — source IP blocked via iptables (`firewall-drop`), automatically unblocked after 10 minutes | `active-responses.log` → Wazuh dashboard | rule.id **651 / 652** | Mitigation (NIST SI.4) |
| 3 | SQL injection (UNION-based) | request against DVWA (`vulnerabilities/sqli`) | Wazuh (Apache log analysis) **and** Suricata (custom rule) | `access.log` + `eve.json` → Wazuh dashboard | rule.id **31106** / sid **1000001** | T1190 — Exploit Public-Facing Application |

## Screenshots

This image shows the detection of a nmap scan on the agent
![Nmap alert in Wazuh dashboard](screenshots/01_wazuh_nmap_alerts.png)

This image shows the ssh brute force attack being successful
![Nmap alert in Wazuh dashboard](screenshots/03_kali_hydra_success.png)

This image shows the detection of a ssh brute force attack on the agent
![Nmap alert in Wazuh dashboard](screenshots/04_wazuh_ssh_blocked.png)

This image shows the agent blocking the IP of the attacker before unblocking it a few minutes later
![Nmap alert in Wazuh dashboard](screenshots/05_wazuh_block_kali_ip.png)

This image shows the agent's firewall successfully blocking the attacker's IP
![Nmap alert in Wazuh dashboard](screenshots/06_agent_iptables_after_block.png)

These images shows the ssh brute force attack failing
![Nmap alert in Wazuh dashboard](screenshots/07_kali_hydra_fail.png)

![Nmap alert in Wazuh dashboard](screenshots/08_kali_hydra_fail.png)

This image shows the agent detection a nmap scan and an SQL injection attack 
![Nmap alert in Wazuh dashboard](screenshots/09_wazuh_detect_nmap&SQL-injection.png)

## Custom Suricata rules

File: `suricata/custom.rules`

```
# SQLi - UNION SELECT in the URI
alert http any any -> $HOME_NET any (msg:"CUSTOM SQLi - UNION SELECT attempt in URI"; flow:to_server,established; http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; classtype:web-application-attack; sid:1000001; rev:1;)

# Nmap scan (SYN packet threshold)
alert tcp any any -> $HOME_NET any (msg:"CUSTOM Possible Nmap SYN scan detected"; flags:S; threshold:type both, track by_src, count 10, seconds 5; classtype:attempted-recon; sid:1000003; rev:2;)

# SSH brute force (network connection-rate threshold)
alert tcp any any -> $HOME_NET 22 (msg:"CUSTOM Possible SSH brute force - high connection rate"; flow:to_server; flags:S; threshold:type both, track by_src, count 8, seconds 20; classtype:attempted-recon; sid:1000004; rev:1;)
```

These rules fill gaps left by the default ruleset: for example, a simple manual SQL injection (`UNION SELECT` style) isn't always covered by standard Emerging Threats rules, which mostly target automated tools (sqlmap) or more specific patterns.

## Active response (Wazuh)

Configuration added to `ossec.conf` (manager):

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>defined-agent</location>
  <agent_id>001</agent_id>
  <rules_id>5763</rules_id>
  <timeout>600</timeout>
</active-response>
```

After 8 failed SSH authentication attempts within less than 2 minutes (rule 5763), the source IP is automatically blocked via `iptables` on the target machine, then unblocked after 10 minutes.

## Mini-SOAR: Automated Wazuh Alert Triage

The lab proves **detection**; this module proves **automation**. A Python script reads Wazuh alerts, enriches them with threat intelligence, computes a severity score, and sends a formatted notification to Discord, the way a SOC analyst would during first-level triage.

### Architecture

```mermaid
flowchart LR
    A[Wazuh manager<br/>alerts.json] -->|scp| B[Python script<br/>analyst workstation]
    B --> C[Rule filtering<br/>5763, 31106]
    C --> D[AbuseIPDB<br/>VirusTotal]
    D --> E[MITRE ATT&CK<br/>+ score 0-100]
    E --> F[Discord webhook]
```

The script runs on the **analyst workstation** (Windows), not on the manager or the agents: it consumes a copy of the manager's alerts file.

### Features

- **Ingestion** of `alerts.json` (one JSON alert per line) with filtering by rule ID
- **Enrichment** of the source IP through the AbuseIPDB API (confidence score, number of reports, country) and VirusTotal (number of engines flagging the IP as malicious)
- **MITRE ATT&CK mapping**: technique carried by the Wazuh rule, with its human-readable name
- **Severity score** (0 to 100): rule level × 5, + 40% of the AbuseIPDB score, + 3 points per malicious VirusTotal engine (capped at 10), ranked as LOW / MEDIUM / CRITICAL
- **Recommended action** attached to each alert type
- **Discord notification** (embed colored by severity) for alerts above a threshold
- Per-IP request caching and compliance with free-tier API quotas

### Covered Alerts

| Wazuh rule | Detection | MITRE ATT&CK |
|---|---|---|
| 5763 | SSH brute force | T1110 |
| 31106 | Web attack (SQL injection) | T1190 |

### Result

![Discord notifications](screenshots/Discord-notifications.png)

### Installation and Usage

```bash
pip install -r requirements.txt

# API keys and webhook via environment variables (never in the code)
set ABUSEIPDB_KEY=...
set VT_KEY=...
set DISCORD_WEBHOOK=...

# Copy the alerts from the Wazuh manager
scp wazuh-user@<MANAGER_IP>:/tmp/alerts.json data/alerts.json

python main.py
```

A sample file, `alerts.sample.json`, lets you test without the lab.

### Known Limitations

- The lab IPs are **private** (`192.168.56.0/24`): AbuseIPDB and VirusTotal have no reputation data to return for them. A **demo mode** (`DEMO_IP`) substitutes a public IP known to be malicious to validate the enrichment pipeline; these alerts are tagged `[DEMO]`.
- Alerts are retrieved **manually** (`scp`) rather than through the Wazuh API.
- No deduplication: each run processes every alert in the file.
- Suricata alerts (Nmap scans) are not handled yet.
- MITRE mapping and recommended actions are hardcoded for the covered rules.

## Challenges encountered and resolved

- **Silent active response**: the `<active-response>` block had been left commented out by mistake in `ossec.conf`, preventing execution despite detection working correctly — diagnosed by comparing manager and agent logs.
- **SSH correlation rule**: the official rule 5720 didn't match the rule chain actually triggered in this Wazuh version (4.14); the correct rule (5763) was identified by inspecting the ruleset directly.

## Possible improvements

- Extend the custom Suricata rules (encoding variants, other injection patterns).
- Add an active response for web attacks (block after repeated SQLi detections).
- Centralize more logs (MariaDB logs, full system logs).

### Future Improvements

- [ ] Daily report in Markdown/HTML
- [ ] Read alerts through the Wazuh API
- [ ] Support for Suricata alerts
- [ ] Scheduled execution on the manager (cron / systemd)

## Stack used

- VirtualBox
- Wazuh 4.14 (manager + agent)
- Suricata (Emerging Threats ruleset + custom rules)
- Kali Linux
- Ubuntu Server 24.04 LTS, Apache, MariaDB, DVWA
