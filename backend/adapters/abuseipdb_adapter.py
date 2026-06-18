import requests

from config import get_settings
from services.demo_mode import demo_abuseipdb_check, is_demo_mode


class AbuseIpdbAdapter:
    base_url = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key if api_key is not None else get_settings().ABUSEIPDB_API_KEY

    def configured(self) -> bool:
        if is_demo_mode():
            return True
        return bool(self.api_key)

    def check_ip(self, ip_address: str) -> dict:
        if is_demo_mode():
            return demo_abuseipdb_check(ip_address)
        if not self.configured():
            return {"success": False, "provider": "abuseipdb", "error": "AbuseIPDB API key is not configured"}
        try:
            response = requests.get(
                self.base_url,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": ""},
                timeout=15,
            )
            if response.status_code >= 400:
                return {"success": False, "provider": "abuseipdb", "status_code": response.status_code, "error": _safe_error(response)}
            data = response.json().get("data") or {}
            return {
                "success": True,
                "provider": "abuseipdb",
                "ip_address": data.get("ipAddress") or ip_address,
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "totalReports": data.get("totalReports"),
                "countryCode": data.get("countryCode"),
                "usageType": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "lastReportedAt": data.get("lastReportedAt"),
                "raw": data,
            }
        except Exception as exc:
            return {"success": False, "provider": "abuseipdb", "error": str(exc) or exc.__class__.__name__}

    def test_connection(self) -> dict:
        if is_demo_mode():
            return {"success": True, "configured": True, "error": None, "mode": "simulated"}
        if not self.configured():
            return {"success": False, "configured": False, "error": "AbuseIPDB API key is not configured"}
        result = self.check_ip("8.8.8.8")
        return {"success": bool(result.get("success")), "configured": True, "error": result.get("error")}


def _safe_error(response) -> str:
    try:
        body = response.json()
        errors = body.get("errors") or []
        if errors:
            return "; ".join(str(item.get("detail") or item) for item in errors)
        return body.get("message") or response.text[:300]
    except Exception:
        return response.text[:300] or f"HTTP {response.status_code}"
