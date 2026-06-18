import base64
import hashlib
import ipaddress
import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import urllib3

from config import get_settings
from services.demo_mode import demo_blocked_ips, demo_pfsense_connection, is_demo_mode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("zerotrustx.pfsense")


class PfSenseAdapter:
    def __init__(
        self,
        host: str = None,
        username: str = None,
        password: str = None,
        block_alias: str = None,
        verify_ssl: bool = None,
        ca_cert_text: str = None,
        ca_cert_path: str = None,
        timeout: int = None,
    ):
        s = get_settings()
        self.host = host if host is not None else s.PFSENSE_HOST
        self.username = username if username is not None else s.PFSENSE_USERNAME
        self.password = password if password is not None else s.PFSENSE_PASSWORD
        self.default_alias = block_alias if block_alias is not None else s.PFSENSE_BLOCK_ALIAS
        self.verify_ssl = bool(verify_ssl) if verify_ssl is not None else bool(getattr(s, "PFSENSE_VERIFY_SSL", False))
        self.ca_cert_text = ca_cert_text if ca_cert_text is not None else getattr(s, "PFSENSE_CA_CERT_TEXT", "")
        self.ca_cert_path = ca_cert_path if ca_cert_path is not None else getattr(s, "PFSENSE_CA_CERT_PATH", "")
        try:
            self.timeout = max(1, min(int(timeout if timeout is not None else getattr(s, "PFSENSE_TIMEOUT", 10)), 120))
        except (TypeError, ValueError):
            self.timeout = 10
        creds = base64.b64encode(f"{self.username or ''}:{self.password or ''}".encode()).decode()
        self.headers = {"Authorization": f"Basic {creds}", "Content-Type": "application/json"}
        self.base = self._base_url(self.host)

    @staticmethod
    def _base_url(host: str) -> str:
        if not host:
            return ""
        candidate = host.rstrip("/")
        if not candidate.startswith(("http://", "https://")):
            candidate = f"https://{candidate}"
        parsed = urlparse(candidate)
        netloc = parsed.netloc or parsed.path
        return f"{parsed.scheme}://{netloc}/api/v1"

    def is_configured(self) -> bool:
        if is_demo_mode():
            return True
        return all([self.host, self.username, self.password, self.default_alias])

    @staticmethod
    def _clean_error(error: Exception) -> str:
        text = str(error) or error.__class__.__name__
        return text[:500]

    def _verify_arg(self):
        if not self.verify_ssl:
            return False
        cert_text = (self.ca_cert_text or "").strip()
        cert_path = (self.ca_cert_path or "").strip()
        if cert_text:
            if "BEGIN CERTIFICATE" not in cert_text or "END CERTIFICATE" not in cert_text:
                raise ValueError("Invalid CA certificate format.")
            digest = hashlib.sha256(cert_text.encode("utf-8")).hexdigest()[:16]
            path = Path(tempfile.gettempdir()) / f"pfsense-ca-{digest}.crt"
            if not path.exists() or path.read_text(encoding="utf-8", errors="ignore") != cert_text:
                path.write_text(cert_text + "\n", encoding="utf-8")
            return str(path)
        if cert_path:
            path = Path(cert_path)
            if not path.exists() or not path.is_file():
                raise ValueError("pfSense CA certificate path does not exist.")
            return str(path)
        return True

    def test_connection(self) -> dict:
        if is_demo_mode():
            return demo_pfsense_connection()
        if not self.is_configured():
            return {
                "success": False,
                "status": "not_configured",
                "message": "pfSense is not configured",
                "connected": False,
                "error": None,
            }

        import requests as req

        try:
            verify_arg = self._verify_arg()
        except Exception as e:
            return {
                "success": False,
                "status": "error",
                "message": "pfSense connection failed",
                "connected": False,
                "error": str(e),
            }

        last_transport_error = None
        for path in ("/system/version", "/diagnostics/system", "/firewall/alias"):
            try:
                r = req.get(
                    f"{self.base}{path}",
                    headers=self.headers,
                    verify=verify_arg,
                    timeout=self.timeout,
                )
            except req.exceptions.ConnectTimeout:
                last_transport_error = f"Connection timed out reaching {self.host}"
                continue
            except req.exceptions.ConnectionError as e:
                msg = str(e).lower()
                if "refused" in msg:
                    last_transport_error = f"Connection refused by {self.host} (check that the REST API plugin is enabled)"
                elif "name or service not known" in msg or "nodename" in msg or "getaddrinfo" in msg:
                    last_transport_error = f"Cannot resolve hostname '{self.host}'"
                else:
                    last_transport_error = f"Network error: {self._clean_error(e)}"
                continue
            except req.exceptions.SSLError:
                last_transport_error = "TLS verification failed. Check pfSense CA certificate text/path or disable Verify SSL for lab systems."
                continue
            except Exception as e:
                last_transport_error = self._clean_error(e)
                continue

            if r.status_code == 200:
                version = None
                try:
                    version = (r.json() or {}).get("data", {}).get("version")
                except Exception:
                    pass
                return {
                    "success": True,
                    "status": "connected",
                    "message": "pfSense connection successful",
                    "connected": True,
                    "error": None,
                    "version": version,
                }
            if r.status_code == 401:
                return {
                    "success": False,
                    "status": "error",
                    "message": "pfSense connection failed",
                    "connected": False,
                    "error": "Authentication failed: invalid username or password",
                }
            if r.status_code == 403:
                return {
                    "success": False,
                    "status": "error",
                    "message": "pfSense connection failed",
                    "connected": False,
                    "error": "Forbidden - check API user permissions",
                }
            if r.status_code == 404:
                continue
            last_transport_error = f"HTTP {r.status_code} from {path}"

        return {
            "success": False,
            "status": "error",
            "message": "pfSense connection failed",
            "connected": False,
            "error": last_transport_error or "No reachable pfSense REST endpoint",
        }

    def _get_alias(self, alias_name: str) -> dict:
        if is_demo_mode():
            return {"id": "demo-alias", "name": alias_name, "address": " ".join(sorted(demo_blocked_ips()))}
        import requests as req

        if not self.is_configured():
            raise ValueError("pfSense is not configured")
        r = req.get(f"{self.base}/firewall/alias", headers=self.headers, verify=self._verify_arg(), timeout=self.timeout)
        r.raise_for_status()
        entries = r.json().get("data", [])
        target = next((a for a in entries if a.get("name") == alias_name), None)
        if not target:
            raise ValueError(f"Alias '{alias_name}' not found on pfSense. Create it first.")
        return target

    def add_to_alias(self, ip: str, alias: str = None) -> dict:
        if is_demo_mode():
            ipaddress.ip_address(str(ip))
            alias = alias or self.default_alias
            blocked = demo_blocked_ips()
            already = ip in blocked
            blocked.add(ip)
            return {
                "success": True,
                "message": "Already in alias" if already else "IP added to alias",
                "alias": alias,
                "ip": ip,
                "total_entries": len(blocked),
            }
        import requests as req

        ipaddress.ip_address(str(ip))
        alias = alias or self.default_alias
        target = self._get_alias(alias)
        existing = [x for x in (target.get("address") or "").split() if x]
        if ip in existing:
            return {
                "success": True,
                "message": "Already in alias",
                "alias": alias,
                "ip": ip,
                "total_entries": len(existing),
            }
        existing.append(ip)
        put = req.put(
            f"{self.base}/firewall/alias",
            json={"id": target["id"], "address": " ".join(existing)},
            headers=self.headers,
            verify=self._verify_arg(),
            timeout=self.timeout,
        )
        put.raise_for_status()
        apply_r = req.post(f"{self.base}/firewall/apply", headers=self.headers, verify=self._verify_arg(), timeout=self.timeout)
        apply_r.raise_for_status()
        return {"success": True, "alias": alias, "ip": ip, "total_entries": len(existing)}

    def remove_from_alias(self, ip: str, alias: str = None) -> dict:
        if is_demo_mode():
            ipaddress.ip_address(str(ip))
            alias = alias or self.default_alias
            blocked = demo_blocked_ips()
            blocked.discard(ip)
            return {"success": True, "removed": ip, "alias": alias, "total_entries": len(blocked)}
        import requests as req

        ipaddress.ip_address(str(ip))
        alias = alias or self.default_alias
        target = self._get_alias(alias)
        existing = [x for x in (target.get("address") or "").split() if x and x != ip]
        put = req.put(
            f"{self.base}/firewall/alias",
            json={"id": target["id"], "address": " ".join(existing)},
            headers=self.headers,
            verify=self._verify_arg(),
            timeout=self.timeout,
        )
        put.raise_for_status()
        apply_r = req.post(f"{self.base}/firewall/apply", headers=self.headers, verify=self._verify_arg(), timeout=self.timeout)
        apply_r.raise_for_status()
        return {"success": True, "removed": ip, "alias": alias, "total_entries": len(existing)}

    def list_alias_ips(self, alias: str = None) -> dict:
        if is_demo_mode():
            alias = alias or self.default_alias
            entries = sorted(demo_blocked_ips())
            return {"success": True, "alias": alias, "ips": entries, "total_entries": len(entries)}
        alias = alias or self.default_alias
        target = self._get_alias(alias)
        entries = [x for x in (target.get("address") or "").split() if x]
        return {"success": True, "alias": alias, "ips": entries, "total_entries": len(entries)}

    def check_ip(self, ip: str, alias: str = None) -> dict:
        if is_demo_mode():
            ipaddress.ip_address(str(ip))
            alias = alias or self.default_alias
            return {
                "success": True,
                "ip": ip,
                "alias": alias,
                "blocked": ip in demo_blocked_ips(),
            }
        ipaddress.ip_address(str(ip))
        data = self.list_alias_ips(alias)
        return {
            "success": True,
            "ip": ip,
            "alias": data.get("alias"),
            "blocked": ip in set(data.get("ips") or []),
        }

    def get_logs(self, src_ip: str = None) -> list:
        if is_demo_mode():
            entries = []
            for ip in sorted(demo_blocked_ips()):
                if src_ip and src_ip != ip:
                    continue
                entries.append(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "source_ip": ip,
                        "action": "block",
                        "alias": self.default_alias,
                        "message": "Demo pfSense blocklist entry",
                    }
                )
            return entries
        import requests as req

        params = {}
        if src_ip:
            params["src"] = src_ip
        r = req.get(
            f"{self.base}/firewall/log",
            headers=self.headers,
            params=params,
            verify=self._verify_arg(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json().get("data", [])
