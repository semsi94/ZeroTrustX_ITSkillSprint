import json
import logging
import socket
import time
from datetime import datetime, timezone
import hashlib
from typing import Optional
from urllib.parse import unquote, urlparse

import urllib3

from config import get_settings
from core.splunk_normalizer import normalize_splunk_event
from services.demo_mode import (
    demo_export_search,
    demo_fired_alerts,
    demo_saved_searches,
    demo_splunk_connection,
    is_demo_mode,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("zerotrustx.splunk")

SPLUNK_CONNECT_TIMEOUT = 10
SPLUNK_SEARCH_TIMEOUT = 30
SPLUNK_HEC_TIMEOUT = 10
# Back-compat alias used by other modules
SPLUNK_TIMEOUT_SECONDS = SPLUNK_CONNECT_TIMEOUT


def ensure_search_prefix(spl: str) -> str:
    spl = spl.strip()
    if not spl.lower().startswith("search "):
        return "search " + spl
    return spl


class SplunkAdapter:
    """Adapter that talks to Splunk management REST and HEC."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hec_token: Optional[str] = None,
        hec_url: Optional[str] = None,
        index: Optional[str] = None,
        scheme: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
    ):
        s = get_settings()
        self.host = host if host is not None else s.SPLUNK_HOST
        self.port = int(port) if port is not None else s.SPLUNK_PORT
        self.scheme = (scheme if scheme is not None else s.SPLUNK_SCHEME or "https").strip() or "https"
        self.username = username if username is not None else s.SPLUNK_USERNAME
        self.password = password if password is not None else s.SPLUNK_PASSWORD
        self.hec_token = (hec_token if hec_token is not None else s.SPLUNK_HEC_TOKEN or "").strip()
        self.hec_url = (hec_url if hec_url is not None else s.SPLUNK_HEC_URL or "").strip()
        self.default_index = (
            index if index is not None else getattr(s, "SPLUNK_DEFAULT_INDEX", "*") or "*"
        ).strip() or "*"
        self.verify_ssl = bool(verify_ssl) if verify_ssl is not None else bool(s.SPLUNK_VERIFY_SSL)

    def is_configured(self) -> bool:
        # Search API is the minimum required surface. HEC is optional.
        if is_demo_mode():
            return True
        return all([self.host, self.port, self.username, self.password])

    def missing_keys(self) -> list[str]:
        if is_demo_mode():
            return []
        missing = []
        if not self.host:
            missing.append("SPLUNK_HOST")
        if not self.port:
            missing.append("SPLUNK_PORT")
        if not self.username:
            missing.append("SPLUNK_USERNAME")
        if not self.password:
            missing.append("SPLUNK_PASSWORD")
        return missing

    def hec_configured(self) -> bool:
        if is_demo_mode():
            return True
        return bool(self.hec_token and self.hec_url)

    def _connect(self, timeout: int = SPLUNK_TIMEOUT_SECONDS):
        import splunklib.client as client

        kwargs = dict(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            scheme=self.scheme,
        )
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            try:
                return client.connect(verify=self.verify_ssl, **kwargs)
            except TypeError:
                return client.connect(**kwargs)
        finally:
            socket.setdefaulttimeout(old_timeout)

    def _smoke_search(self, svc, timeout: int = SPLUNK_SEARCH_TIMEOUT) -> dict:
        """Exercise Search API job creation via POST and JSON result parsing."""
        import splunklib.results as results

        query = ensure_search_prefix("index=* | head 1")
        deadline = time.monotonic() + timeout
        try:
            job = svc.jobs.create(
                query,
                earliest_time="0",
                latest_time="now",
            )
            while not job.is_done():
                if time.monotonic() >= deadline:
                    return {"ok": False, "error": f"Search API timed out after {timeout}s"}
                time.sleep(0.25)

            reader = results.JSONResultsReader(job.results(output_mode="json", count=1))
            for _ in reader:
                pass
            return {"ok": True, "query": query}
        except Exception as e:
            return {"ok": False, "error": str(e), "query": query}

    def _test_hec(self, timeout: int = SPLUNK_HEC_TIMEOUT) -> dict:
        import requests as req

        event = {
            "event": {
                "source": "zerotrustx",
                "event_type": "connection_test",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "sourcetype": "zerotrustx:connection_test",
            "time": time.time(),
        }
        try:
            response = req.post(
                self.hec_url,
                headers={"Authorization": f"Splunk {self.hec_token}"},
                json=event,
                verify=self.verify_ssl,
                timeout=timeout,
            )
            body = None
            try:
                body = response.json()
            except Exception:
                body = response.text[:500]

            if response.status_code not in (200, 201):
                return {
                    "ok": False,
                    "error": f"HEC returned HTTP {response.status_code}: {body}",
                }

            if isinstance(body, dict) and body.get("code") not in (0, None):
                return {"ok": False, "error": f"HEC rejected event: {body}"}

            return {"ok": True, "response": body}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def test_connection(self) -> dict:
        """Verify Search API credentials. HEC is tested if configured but
        does not block overall success — the analyst should be able to read
        from Splunk even if write-back is not yet wired up.
        """
        if is_demo_mode():
            return demo_splunk_connection()
        missing = self.missing_keys()
        if missing:
            return {
                "connected": False,
                "error": f"Missing config: {', '.join(missing)}",
                "rest_connected": False,
                "hec_connected": False,
            }

        # Step 1: authenticate
        try:
            svc = self._connect()
        except Exception as e:
            msg = str(e) or e.__class__.__name__
            low = msg.lower()
            if "unauthorized" in low or "401" in low:
                friendly = "Authentication failed: invalid username or password"
            elif "timed out" in low or "timeout" in low:
                friendly = f"Connection timed out reaching {self.host}:{self.port}"
            elif "refused" in low:
                friendly = f"Connection refused by {self.host}:{self.port} (check port and that Splunkd is running)"
            elif "ssl" in low or "certificate" in low:
                friendly = f"TLS handshake failed: {msg}"
            elif "name or service not known" in low or "nodename nor servname" in low or "getaddrinfo" in low:
                friendly = f"Cannot resolve hostname '{self.host}'"
            else:
                friendly = f"REST API connect failed: {msg}"
            return {
                "connected": False,
                "error": friendly,
                "rest_connected": False,
                "hec_connected": False,
            }

        token = getattr(svc, "token", None)
        if not token:
            return {
                "connected": False,
                "error": "REST API authenticated but returned no session token",
                "rest_connected": False,
                "hec_connected": False,
            }

        version = "unknown"
        try:
            info = svc.info
            if info:
                version = info.get("version", "unknown")
        except Exception as info_err:
            log.debug("svc.info unavailable (non-fatal): %s", info_err)

        # Step 2: smoke-search (non-fatal; surface as warning if it fails)
        search_ok = True
        search_warning = None
        try:
            search = self._smoke_search(svc)
            if not search["ok"]:
                search_ok = False
                search_warning = f"Search API smoke test failed: {search['error']}"
        except Exception as e:
            search_ok = False
            search_warning = f"Search API smoke test errored: {e}"

        # Step 3: HEC (only if configured; non-fatal)
        hec_connected = False
        hec_error = None
        if self.hec_configured():
            hec = self._test_hec()
            hec_connected = hec["ok"]
            if not hec["ok"]:
                hec_error = hec["error"]
        else:
            hec_error = "Not configured"

        saved_access = False
        alerts_access = False
        saved_error = None
        alerts_error = None
        if search_ok:
            saved = self.management_get("/servicesNS/-/-/saved/searches", {"count": 1}, timeout=10)
            saved_access = bool(saved.get("ok"))
            saved_error = saved.get("error")
            fired = self.management_get("/services/alerts/fired_alerts", {"count": 1}, timeout=10)
            alerts_access = bool(fired.get("ok"))
            alerts_error = fired.get("error")

        # Overall: authenticated REST = connected. Surface partial failures via fields.
        notes = []
        if search_warning:
            notes.append(search_warning)
        if self.hec_configured() and not hec_connected:
            notes.append(f"HEC test failed: {hec_error}")

        return {
            "connected": search_ok,
            "error": "; ".join(notes) if notes else None,
            "version": version,
            "rest_connected": True,
            "search_connected": search_ok,
            "hec_connected": hec_connected,
            "hec_error": hec_error,
            "saved_searches_accessible": saved_access,
            "saved_searches_error": saved_error,
            "alerts_accessible": alerts_access,
            "alerts_error": alerts_error,
            "search_warning": search_warning,
        }

    def search(self, spl: str, earliest: str = "-24h", latest: str = "now") -> list:
        if is_demo_mode():
            query = ensure_search_prefix(spl)
            if earliest:
                query = f"{query} earliest={earliest}"
            if latest:
                query = f"{query} latest={latest}"
            return demo_export_search(query).get("events", [])
        import splunklib.client as client  # noqa: F401
        import splunklib.results as results

        spl = ensure_search_prefix(spl)
        svc = self._connect()
        kwargs = {"earliest_time": earliest, "latest_time": latest}
        if earliest in ("0", "all", "alltime"):
            kwargs["earliest_time"] = "0"
            kwargs.pop("latest_time", None)
        job = svc.jobs.create(spl, **kwargs)
        while not job.is_done():
            time.sleep(0.5)
        reader = results.JSONResultsReader(job.results(output_mode="json"))
        return [r for r in reader if isinstance(r, dict)]

    def _management_url(self, path: str) -> str:
        return f"{self.scheme}://{self.host}:{self.port}{path}"

    @staticmethod
    def _first(raw: dict, keys: list[str]) -> str:
        for key in keys:
            value = raw.get(key)
            if value not in (None, ""):
                return str(value)
        return ""

    @classmethod
    def normalize_event(cls, raw_event) -> dict:
        return normalize_splunk_event(raw_event)

    @staticmethod
    def _readable_http_error(response) -> str:
        body = response.text[:1000] if getattr(response, "text", None) else ""
        try:
            parsed = response.json()
            body = json.dumps(parsed)[:1000]
        except Exception:
            pass
        return f"Splunk Search API returned HTTP {response.status_code}: {body or response.reason}"

    def export_search(self, spl: str, timeout: int = SPLUNK_SEARCH_TIMEOUT) -> dict:
        """Run a Splunk Search API export and parse newline-delimited JSON."""
        if is_demo_mode():
            return demo_export_search(spl)
        import requests as req

        if not self.is_configured():
            return {
                "events": [],
                "status_code": None,
                "error": f"Missing config: {', '.join(self.missing_keys())}",
            }

        spl = ensure_search_prefix(spl)
        try:
            response = req.post(
                self._management_url("/services/search/jobs/export"),
                auth=(self.username, self.password),
                data={"search": spl, "output_mode": "json"},
                verify=self.verify_ssl,
                timeout=timeout,
            )
            log.info("Splunk export HTTP status=%s", response.status_code)
            if response.status_code >= 400:
                return {
                    "events": [],
                    "status_code": response.status_code,
                    "error": self._readable_http_error(response),
                }

            events = []
            parse_errors = 0
            for line in response.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    parse_errors += 1
                    continue
                if isinstance(obj, dict) and "result" in obj:
                    raw = obj.get("result")
                elif isinstance(obj, dict) and any(k in obj for k in ("_raw", "_time", "index", "sourcetype", "host")):
                    raw = obj
                else:
                    raw = None
                if raw:
                    events.append(self.normalize_event(raw))

            error = None
            if parse_errors and not events:
                error = "Splunk returned data, but no JSON result rows could be parsed"
            log.info("Splunk export parsed events=%s parse_errors=%s", len(events), parse_errors)
            return {
                "events": events,
                "status_code": response.status_code,
                "error": error,
            }
        except req.exceptions.Timeout:
            msg = f"Splunk Search API timed out after {timeout}s"
            log.info(msg)
            return {"events": [], "status_code": None, "error": msg}
        except req.exceptions.SSLError as e:
            msg = f"Splunk TLS/SSL error: {e}"
            log.info(msg)
            return {"events": [], "status_code": None, "error": msg}
        except Exception as e:
            msg = str(e) or e.__class__.__name__
            log.info("Splunk export failed: %s", msg)
            return {"events": [], "status_code": None, "error": msg}

    def management_get(self, path: str, params: Optional[dict] = None, timeout: int = SPLUNK_CONNECT_TIMEOUT) -> dict:
        if is_demo_mode():
            return {"ok": True, "data": {}, "status_code": 200}
        import requests as req

        if not self.is_configured():
            return {"ok": False, "error": f"Missing config: {', '.join(self.missing_keys())}"}
        try:
            merged = {"output_mode": "json"}
            if params:
                merged.update(params)
            response = req.get(
                self._management_url(path),
                auth=(self.username, self.password),
                params=merged,
                verify=self.verify_ssl,
                timeout=timeout,
            )
            log.info("Splunk management GET path=%s status=%s", path, response.status_code)
            if response.status_code >= 400:
                return {"ok": False, "error": self._readable_http_error(response), "status_code": response.status_code}
            return {"ok": True, "data": response.json(), "status_code": response.status_code}
        except Exception as e:
            return {"ok": False, "error": str(e) or e.__class__.__name__}

    @staticmethod
    def _entry_content(entry: dict) -> dict:
        content = entry.get("content") if isinstance(entry, dict) else {}
        return content if isinstance(content, dict) else {}

    @staticmethod
    def _entry_id(entry: dict) -> str:
        for key in ("id", "name", "title"):
            value = entry.get(key)
            if value:
                return str(value)
        return ""

    @staticmethod
    def _clean_saved_search_label(value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        candidate = raw
        if raw.startswith(("http://", "https://")):
            parsed = urlparse(raw)
            tail = parsed.path.rstrip("/").split("/")[-1]
            candidate = tail or raw
        for _ in range(2):
            decoded = unquote(candidate)
            if decoded == candidate:
                break
            candidate = decoded
        return candidate.replace("+", " ").strip()

    @staticmethod
    def _to_int(value, default: int = 0) -> int:
        try:
            if isinstance(value, list):
                value = value[0] if value else default
            return int(value)
        except Exception:
            return default

    def list_saved_searches(self) -> dict:
        if is_demo_mode():
            return demo_saved_searches()
        res = self.management_get("/servicesNS/-/-/saved/searches", {"count": 0}, timeout=SPLUNK_SEARCH_TIMEOUT)
        if not res.get("ok"):
            return {"items": [], "error": res.get("error")}
        entries = (res.get("data") or {}).get("entry") or []
        items = []
        for entry in entries:
            content = self._entry_content(entry)
            search = content.get("search") or ""
            is_scheduled = str(content.get("is_scheduled", "0")).lower() in {"1", "true", "yes"}
            alert_type = content.get("alert_type") or ""
            actions = content.get("actions") or ""
            alert_condition = content.get("alert_condition") or content.get("alert_condition_search") or ""
            comparator = content.get("alert_comparator") or ""
            threshold = content.get("alert_threshold")
            alert_track = str(content.get("alert.track") or content.get("alert_track") or "0").lower() in {"1", "true", "yes"}
            normalized_alert_type = str(alert_type or "").strip().lower()
            action_names = {action.strip() for action in str(actions or "").split(",") if action.strip()}
            # Splunk 10 may report alert_type="always" for ordinary saved
            # searches. Only classify it as an alert when scheduled or paired
            # with explicit alert behavior.
            alert_like = bool(
                (normalized_alert_type and normalized_alert_type != "always")
                or alert_condition
                or (comparator and threshold not in (None, ""))
                or alert_track
                or (is_scheduled and normalized_alert_type == "always" and bool(action_names))
            )
            item_type = "alert" if alert_like else "report" if is_scheduled or search else "saved_search"
            items.append({
                "id": self._entry_id(entry),
                "name": entry.get("name") or entry.get("title") or "",
                "title": entry.get("title") or entry.get("name") or "",
                "search": search,
                "is_scheduled": is_scheduled,
                "alert_type": alert_type,
                "cron_schedule": content.get("cron_schedule") or "",
                "disabled": str(content.get("disabled", "0")).lower() in {"1", "true", "yes"},
                "actions": actions,
                "description": content.get("description") or "",
                "trigger_condition": alert_condition or comparator or "",
                "alert_condition": alert_condition,
                "alert_comparator": comparator,
                "alert_threshold": threshold,
                "severity": str(content.get("severity") or content.get("alert.severity") or content.get("alert_severity") or "unknown").lower(),
                "last_triggered": content.get("last_triggered_time") or content.get("triggered_time") or content.get("updated") or entry.get("updated") or "",
                "source": "splunk",
                "type": item_type,
            })
        return {"items": items, "error": None}

    def list_fired_alerts(self) -> dict:
        if is_demo_mode():
            return demo_fired_alerts()
        res = self.management_get("/services/alerts/fired_alerts", {"count": 0}, timeout=SPLUNK_SEARCH_TIMEOUT)
        if not res.get("ok"):
            return {"items": [], "error": res.get("error")}
        entries = (res.get("data") or {}).get("entry") or []
        saved_items = []
        try:
            saved_items = self.list_saved_searches().get("items", [])
        except Exception as e:
            log.info("Unable to enrich fired alerts from saved searches: %s", e)
        saved_by_key = {}
        for saved in saved_items:
            for key in (saved.get("id"), saved.get("name"), saved.get("title")):
                if key:
                    saved_by_key[str(key)] = saved

        items = []
        for entry in entries:
            content = self._entry_content(entry)
            severity = content.get("severity") or content.get("alert_severity") or "unknown"
            raw_saved_search_name = (
                content.get("savedsearch_name")
                or content.get("saved_search_name")
                or content.get("savedsearch")
                or content.get("search_name")
                or entry.get("name")
                or entry.get("title")
                or ""
            )
            saved = saved_by_key.get(str(raw_saved_search_name)) or saved_by_key.get(str(entry.get("name") or ""))
            saved_search_name = (
                (saved or {}).get("title")
                or (saved or {}).get("name")
                or self._clean_saved_search_label(raw_saved_search_name)
                or self._clean_saved_search_label(entry.get("title") or "")
                or self._clean_saved_search_label(entry.get("name") or "")
            )
            if saved_search_name in {"", "-", "_"}:
                continue
            alert_id = self._entry_id(entry)
            trigger_time = (
                content.get("trigger_time")
                or content.get("dispatch_time")
                or content.get("triggered_time")
                or content.get("published")
                or entry.get("updated")
                or ""
            )
            search = content.get("search") or (saved or {}).get("search") or ""
            source_ref = alert_id or f"{saved_search_name}:{trigger_time}"
            source_hash = hashlib.sha256(
                json.dumps(
                    {"name": saved_search_name or entry.get("name"), "trigger_time": trigger_time, "source_ref": source_ref},
                    sort_keys=True,
                    default=str,
                ).encode("utf-8")
            ).hexdigest()
            items.append({
                "id": alert_id,
                "name": saved_search_name,
                "severity": str(severity).lower(),
                "status": "pending_approval",
                "trigger_time": trigger_time,
                "saved_search_name": saved_search_name,
                "search_name": saved_search_name,
                "search": search,
                "trigger_condition": content.get("trigger_condition") or (saved or {}).get("trigger_condition") or "",
                "result_count": self._to_int(content.get("result_count") or content.get("triggered_alert_count") or 0),
                "source_ref": source_ref,
                "source_hash": source_hash,
                "sid": content.get("sid") or "",
                "source": "splunk",
            })
        return {"items": items, "error": None}

    def write_to_hec(self, event: dict) -> bool:
        """Write an event to Splunk HEC using the token-bound index."""
        if is_demo_mode():
            return True
        if not self.hec_token or not self.hec_url:
            return False
        import requests as req

        try:
            r = req.post(
                self.hec_url,
                headers={"Authorization": f"Splunk {self.hec_token}"},
                json={"event": event, "time": time.time()},
                verify=self.verify_ssl,
                timeout=SPLUNK_HEC_TIMEOUT,
            )
            return r.status_code in (200, 201)
        except Exception as e:
            log.warning("HEC write failed: %s", e)
            return False
