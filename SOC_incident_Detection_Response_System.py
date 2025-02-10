import json
import requests
import shodan
import pandas as pd

# API Keys
VT_API_KEY = "virustotal_api_key"
ABUSE_IPDB_KEY = "abuseipdb_api_key"
SHODAN_API_KEY = "shodan_api_key"


shodan_client = shodan.Shodan(SHODAN_API_KEY)


def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_IPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    return response.json().get("data", {}).get("abuseConfidenceScore", "N/A")


def check_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})


def check_shodan(ip):
    try:
        data = shodan_client.host(ip)
        return data.get("ports", [])
    except shodan.APIError as e:
        return {"error": str(e)}


def analyze_logs(log_file):
    with open(log_file, "r") as file:
        logs = json.load(file)

    results = []
    for event in logs:
        ip = event.get("ip")
        file_hash = event.get("file_hash")
        event_type = event["event_type"]

        ip_risk_score = check_abuseipdb(ip) if ip else "N/A"
        malware_analysis = check_virustotal(file_hash) if file_hash else "N/A"
        open_ports = check_shodan(ip) if ip else "N/A"

        # Classify the event risk level
        risk_level = "Low"
        if event_type == "brute_force_attempt" and int(ip_risk_score) > 50:
            risk_level = "High"
        elif event_type == "malware_detected" and malware_analysis.get("malicious", 0) > 2:
            risk_level = "Critical"

        results.append({
            "timestamp": event["timestamp"],
            "event_type": event_type,
            "ip": ip,
            "ip_risk_score": ip_risk_score,
            "file_hash": file_hash,
            "malware_detection": malware_analysis,
            "open_ports": open_ports,
            "risk_level": risk_level
        })

    return results


def generate_report(results, output_file="incident_report.csv"):
    df = pd.DataFrame(results)
    df.to_csv(output_file, index=False)
    print(f"Incident report saved as {output_file}")


if __name__ == "__main__":
    results = analyze_logs("security_logs.json")
    generate_report(results)
