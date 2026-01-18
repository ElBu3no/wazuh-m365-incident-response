Wazuh M365 Incident Response

Automated incident response for Microsoft 365 using Wazuh SIEM, threat intelligence enrichment, and email alerting.

📌 About the Project

This repository showcases an automated incident response solution inspired by a real-world phishing case in a Microsoft 365 environment.
The goal is to demonstrate how a Blue Team can detect, analyze, and respond to suspicious activities using Wazuh as a SIEM, custom Python scripting, and external Threat Intelligence sources.

All sensitive information has been sanitized and adapted for educational purposes.

🎯 Objectives

Centralize and analyze Microsoft 365 logs

Detect suspicious login activity (e.g., logins from foreign IPs)

Enrich events with Threat Intelligence data

Reduce false positives using contextual checks

Automate alerting for faster incident response

🧠 Architecture Overview
Microsoft 365
      ↓
Wazuh / OpenSearch (SIEM)
      ↓
Python Analysis Script
      ↓
Threat Intelligence (AbuseIPDB / VirusTotal)
      ↓
User Validation (Active Directory / Entra ID)
      ↓
Automated Email Alert

🔍 How It Works

Log Collection

Queries Office 365 events stored in Wazuh/OpenSearch

Filters events by time window and relevant operations (successful and failed logins)

Analysis & Correlation

Identifies external IP addresses

Checks IP reputation using AbuseIPDB and VirusTotal

Validates the user against Active Directory via LDAPS

Verifies account status (enabled / disabled)

Decision Logic

Applies contextual rules to reduce noise

Flags only actionable security events

Automated Response

Generates enriched alerts

Sends structured email notifications with investigation details

⚙️ Features

Microsoft 365 login monitoring

GeoIP-based country detection

IP reputation scoring (AbuseIPDB)

VirusTotal IP analysis

Active Directory lookup via LDAPS

Account status evaluation (userAccountControl)

Cache system to prevent duplicate alerts

HTML and plain-text email notifications

Fully automated execution (cron / Wazuh Active Response)

🛠️ Requirements

Python 3.9+

Wazuh SIEM

OpenSearch

Microsoft 365 integration enabled in Wazuh

Active Directory with LDAPS enabled

API keys for:

AbuseIPDB

VirusTotal

Azure Communication Services (Email)

🔐 Environment Variables

Create a .env file with the following variables:

OPENSEARCH_URL=
OPENSEARCH_USER=
OPENSEARCH_PASS=

ABUSEIPDB_KEY=
VIRUSTOTAL_API_KEY=

AZURE_CONNECTION_STRING=
AZURE_EMAIL_FROM=
AZURE_EMAIL_TO=

AD_BASE_DN=
AD_BIND_USER=
AD_BIND_PASS=
AD_LDAPS_HOSTS=
AD_LDAPS_PORT=636
AD_CA_FILE=

📁 Project Structure
.
├── monitor_o365.py
├── GeoLite2-Country.mmdb
├── .env
├── README.md

🚀 Usage

Run manually:

python3 monitor_o365.py


Or schedule execution via:

Cron

Wazuh Active Response

SOAR pipeline

⚠️ Disclaimer

This project is intended for educational and defensive security purposes only.
Do not use this code for unauthorized monitoring or without proper approval.

👨‍💻 Author

Lhuan Bueno
Information Security | Blue Team | Automation & SIEM
GitHub: @lhuanbueno
