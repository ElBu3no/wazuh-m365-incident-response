# Wazuh M365 Incident Response

Incident response automation for Microsoft 365 login events using Wazuh, threat intelligence enrichment and email alerting.

---

## About this project

This project was built after a **real phishing incident** involving Microsoft 365 accounts.

The goal was not to create a full SOAR platform, but to show how a **Blue Team can be effective with simple, well-designed automation**.  
By combining Wazuh logs, contextual checks and external threat intelligence, the script helps identify **when a login event actually deserves attention**.

All sensitive information has been anonymized and adapted for educational use.

---

## What this script actually does

- Queries Microsoft 365 login events stored in Wazuh / OpenSearch
- Focuses on logins coming from outside the expected country
- Enriches IPs with:
  - AbuseIPDB reputation
  - VirusTotal analysis
  - GeoIP location
- Validates the user against Active Directory via LDAPS
- Checks whether the account is enabled or disabled
- Applies basic correlation rules to reduce noise
- Sends a clear and actionable email alert

---

## Detection logic (high level)

An alert is generated when:

- A Microsoft 365 login occurs from outside Brazil
- The user exists in Active Directory
- The account is enabled
- The IP reputation is checked (no blind blocking)

A cache mechanism prevents duplicate alerts for the same event.

---

## Why this approach

- Less noise, more context
- No dependency on expensive SOAR tools
- Easy to adapt to different environments
- Focused on decision support, not just alerting

---

## Features

- Microsoft 365 login monitoring (success and failure)
- GeoIP-based country validation
- IP reputation lookup (AbuseIPDB)
- VirusTotal IP enrichment
- Active Directory lookup via LDAPS
- Account status evaluation (userAccountControl)
- Alert deduplication using cache
- HTML and plain-text email notifications
- Designed for automation (cron or Wazuh Active Response)

---

## Disclaimer

This project is intended for **defensive and educational purposes only**.  
Do not deploy in production environments without proper authorization and validation.

---

## Author

**Lhuan Bueno**  
LinkedIn: https://www.linkedin.com/in/lhuanbueno
