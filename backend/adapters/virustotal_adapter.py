import requests

from config import get_settings
from services.demo_mode import demo_virustotal_check, is_demo_mode


class VirusTotalAdapter:
    base_url = "https://www.virustotal.com/api/v3/ip_addresses"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key if api_key is not None else get_settings().VIRUSTOTAL_API_KEY

    def configured(self) -> bool:
        if is_demo_mode():
            return True
        return bool(self.api_key)

    def check_ip(self, ip_address: str) -> dict:
        if is_demo_mode():
            return demo_virustotal_check(ip_address)
        if not self.configured():
            return {"success": False, "provider": "virustotal", "error": "VirusTotal API key is not configured"}
        try:
            response = requests.get(
                f"{self.base_url}/{ip_address}",
                headers={"x-apikey": self.api_key, "Accept": "application/json"},
                timeout=15,
            )
            if response.status_code >= 400:
                return {"success": False, "provider": "virustotal", "status_code": response.status_code, "error": _safe_error(response)}
            attrs = (response.json().get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            return {
                "success": True,
                "provider": "virustotal",
                "ip_address": ip_address,
                "last_analysis_stats": stats,
                "reputation": attrs.get("reputation"),
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
                "network": attrs.get("network"),
                "raw": attrs,
            }
        except Exception as exc:
            return {"success": False, "provider": "virustotal", "error": str(exc) or exc.__class__.__name__}

    def test_connection(self) -> dict:
        if is_demo_mode():
            return {"success": True, "configured": True, "error": None, "mode": "simulated"}
        if not self.configured():
            return {"success": False, "configured": False, "error": "VirusTotal API key is not configured"}
        result = self.check_ip("8.8.8.8")
        return {"success": bool(result.get("success")), "configured": True, "error": result.get("error")}


def _safe_error(response) -> str:
    try:
        body = response.json()
        error = body.get("error") or {}
        return error.get("message") or error.get("code") or response.text[:300]
    except Exception:
        return response.text[:300] or f"HTTP {response.status_code}"
