import requests
import json
import csv
import os
from datetime import datetime

def fetch_cves():
    print("\n🔍 VulnTracker — CVE Vulnerability Scanner")
    print("Fetching latest Critical CVEs...\n")

    # Free NVD API — no key needed
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": 10
    }

    response = requests.get(url, params=params)
    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    results = []

    for item in vulnerabilities:
        cve = item["cve"]
        cve_id = cve["id"]

        # Get description
        description = "No description available"
        for desc in cve.get("descriptions", []):
            if desc["lang"] == "en":
                description = desc["value"][:100]
                break

        # Get CVSS score
        score = "N/A"
        severity = "UNKNOWN"
        try:
            metrics = cve["metrics"]["cvssMetricV31"][0]
            score = metrics["cvssData"]["baseScore"]
            severity = metrics["cvssData"]["baseSeverity"]
        except:
            pass

        # Get published date
        published = cve.get("published", "Unknown")[:10]

        result = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cve_id": cve_id,
            "severity": severity,
            "cvss_score": score,
            "published": published,
            "description": description,
            "action": get_action(severity)
        }

        results.append(result)
        print_result(result)

    save_reports(results)
    return results

def get_action(severity):
    actions = {
        "CRITICAL": "Patch immediately — check if systems affected",
        "HIGH": "Patch within 1 week — assess exposure",
        "MEDIUM": "Patch within 1 month — monitor",
        "LOW": "Schedule patch — low risk"
    }
    return actions.get(severity, "Review and assess")

def print_result(result):
    print("="*60)
    print(f"CVE ID    : {result['cve_id']}")
    print(f"Severity  : {result['severity']}")
    print(f"CVSS Score: {result['cvss_score']}/10")
    print(f"Published : {result['published']}")
    print(f"Details   : {result['description']}")
    print(f"Action    : {result['action']}")
    print("="*60)

def save_reports(results):
    # Save JSON report
    os.makedirs("reports", exist_ok=True)
    with open("reports/vulntracker_report.json", "w") as f:
        json.dump(results, f, indent=2)

    # Save CSV for Splunk
    os.makedirs("logs", exist_ok=True)
    with open("logs/vulntracker_splunk.csv", "w", newline="") as f:
        if results:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)

    print("\n✅ JSON report saved to reports/vulntracker_report.json")
    print("✅ Splunk CSV saved to logs/vulntracker_splunk.csv")
    print("✅ Upload logs/vulntracker_splunk.csv to Splunk now")

if __name__ == "__main__":
    fetch_cves()