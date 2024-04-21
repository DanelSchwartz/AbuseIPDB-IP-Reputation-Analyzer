import requests
import pandas as pd
import json
import ipaddress

# Function to check if an IP is external
def is_external_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

# Function to check the reputation of an IP using the AbuseIPDB API
def check_ip_reputation(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error querying AbuseIPDB for IP {ip}: {response.status_code}")
        return None

def main():
    # Replace 'YOUR_FILE_PATH' with the path to your CSV file
    data_path = 'YOUR_FILE_PATH'
    data = pd.read_csv(data_path)

    # Replace 'YOUR_API_KEY' with your actual AbuseIPDB API key
    api_key = 'YOUR_API_KEY'

    # Check IP reputation for external IPs
    unique_ips = pd.concat([data['Source IP'], data['Destination IP']]).unique()
    external_ips = [ip for ip in unique_ips if is_external_ip(ip)]

    for ip in external_ips:
        result = check_ip_reputation(ip, api_key)
        if result:
            data = result.get('data', {})
            abuse_confidence_score = data.get('abuseConfidenceScore', 0)
            isp = data.get('isp', 'Unknown ISP')
            if abuse_confidence_score >= 25:
                # Now extracting more details
                country = data.get('countryName', 'Unknown Country')
                domain = data.get('domain', 'Unknown Domain')
                usage_type = data.get('usageType', 'Unknown Usage Type')
                last_reported_at = data.get('lastReportedAt', 'Not Reported')
                print(f"Malicious IP: {ip}, Confidence of Abuse: {abuse_confidence_score}%, "
                      f"ISP: {isp}, Country: {country}, Domain: {domain}, "
                      f"Usage Type: {usage_type}, Last Reported At: {last_reported_at}")

if __name__ == "__main__":
    main()
