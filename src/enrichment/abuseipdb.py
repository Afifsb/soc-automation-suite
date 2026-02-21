import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_ip(ip: str) -> dict:
    """
    Query AbuseIPDB for IP reputation
    """
    if not API_KEY:
        return {"error": "Missing API key"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        data = response.json()["data"]

        return {
            "ip": ip,
            "abuse_score": data["abuseConfidenceScore"],
            "country": data["countryCode"],
            "isp": data["isp"],
            "total_reports": data["totalReports"]
        }

    except Exception as e:
        return {"error": str(e)}
