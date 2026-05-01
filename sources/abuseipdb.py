import os
import ipaddress
import requests
from dotenv import load_dotenv
import os

load_dotenv("/opt/project/ghostTrap/.env")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def is_public_ip(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_global
    except ValueError:
        return False


def check_ip(ip, max_age_days=90):
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        raise RuntimeError("ABUSEIPDB_API_KEY is not set")

    if not is_public_ip(ip):
        return None

    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": max_age_days,
        "verbose": "",
    }

    res = requests.get(
        ABUSEIPDB_URL,
        headers=headers,
        params=params,
        timeout=15,
    )

    res.raise_for_status()
    data = res.json().get("data", {})

    return {
        "indicator": ip,
        "provider": "abuseipdb",
        "provider_score": int(data.get("abuseConfidenceScore") or 0),
        "provider_verdict": None,
        "categories": [str(c) for c in data.get("reports", [{}])[0].get("categories", [])] if data.get("reports") else [],
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "total_reports": int(data.get("totalReports") or 0),
        "last_reported_at": data.get("lastReportedAt"),
        "raw_response": data,
    }
