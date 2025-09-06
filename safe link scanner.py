import requests
import base64

# Your VirusTotal API key
api_key = "5eb76b5b73a5e4cdf2351f5517cbc9b103c90e958642402d28ac56d250375eda"

# Ask the user for the URL to scan
url_to_check = input("Enter the URL to scan: ")

# VirusTotal API URL
api_url = "https://www.virustotal.com/api/v3/urls"

# Encode the URL for VirusTotal
url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")

# Send request to VirusTotal
headers = {"x-apikey": api_key}
response = requests.post(api_url, headers=headers, data={"url": url_to_check})

if response.status_code == 200:
    # Fetch the analysis report
    analysis_url = f"{api_url}/{url_id}"
    report = requests.get(analysis_url, headers=headers)
    if report.status_code == 200:
        data = report.json()
        malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        if malicious_count > 0:
            print(f"⚠️ This URL is malicious! ({malicious_count} engines flagged it)")
        else:
            print("✅ This URL seems clean.")
    else:
        print("Error fetching report:", report.status_code, report.text)
else:
    print("Error submitting URL:", response.status_code, response.text)

