# splunk-mini-soc
Hands-on Splunk SOC project simulating brute-force and data-exfiltration detection with Apache logs and MITRE ATT&amp;CK mapping.
**Author:** Manzi Siibo  
**Role Goal:** Cloud Security Analyst / SOC Analyst  
**Platform:** Splunk Enterprise (Free Edition)

---

## 📘 Project Overview

This project demonstrates a hands-on Security Operations Center (SOC) workflow using Splunk Enterprise.  
I built and documented a mini SOC environment that simulates real-world detection engineering and incident monitoring.

Key capabilities shown:
- Ingesting and parsing Apache web logs  
- Detecting brute-force and exfiltration patterns  
- Visualizing activity through SPL queries and reports  
- Mapping detections to MITRE ATT&CK techniques

---

## ⚙️ Environment Setup

| Component | Details |
|------------|----------|
| OS | Windows 10 / 11 (Acer Laptop) |
| Tool | Splunk Enterprise Free |
| Data Source | Apache_2k.log (sample web server logs) |
| Index Created | `weblogs1` |
| Host | `demo-host` |

---

## 🧩 Workflow Summary

### 1️⃣ Data Ingestion
- Uploaded Apache web logs (`Apache_2k.log`)
- Source type: `access_combined`
- Custom index: `weblogs1`

### 2️⃣ Field Extraction
Used SPL to extract key fields from raw logs:
```spl
index=weblogs1
| rex field=_raw "(?<client_ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[(?<timestamp>[^\]]+)\] \"(?<method>\S+) (?<uri>\S+) (?<protocol>HTTP/\S+)\" (?<status>\d{3}) (?<bytes>\d+)"
| table client_ip, method, uri, status, bytes

3️⃣ Detections

Brute Force Attempts

index=weblogs1 status=401
| stats count by client_ip
| where count > 5


Data Exfiltration (no hits expected in sample)

index=weblogs1 method=GET
| stats sum(bytes) as total_bytes by client_ip
| where total_bytes > 5000000   
