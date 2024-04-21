# AbuseIPDB-IP-Reputation-Analyzer
This tool automates the process of checking IP reputations by querying the AbuseIPDB API to identify potentially malicious external IP addresses within firewall logs. It was developed as part of a cybersecurity exam to aid in proactive network defense.

## Features

- Filters out private and internal IP ranges.
- Checks external IP addresses against AbuseIPDB.
- Flags IPs with high abuse confidence scores.
- Extracts and reports relevant details such as IP, abuse confidence score, and ISP information.

## Usage

Before running the script, ensure you replace `YOUR_API_KEY` with your actual AbuseIPDB API key and set the correct file path to your CSV log file.

```bash
python abuseipdb.py
```

## Exam Context
This script was created for an examination to showcase practical application of Python in cybersecurity analysis.


