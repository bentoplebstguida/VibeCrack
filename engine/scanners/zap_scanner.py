"""
VibeCrack Engine - OWASP ZAP Integration Scanner

Integrates with OWASP ZAP (Zed Attack Proxy) running as a daemon in Docker.
Uses ZAP's API to perform automated active/passive scanning and imports
the findings into VibeCrack's vulnerability database.

Requires ZAP running with API enabled (see docker-compose.yml).
"""

import logging
import os
import time
from typing import Any, Optional

import requests

from engine.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# ZAP API configuration
ZAP_API_URL = os.environ.get("ZAP_API_URL", "http://hackerpa-zap:8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")  # disabled by default in docker-compose

# Timeout for waiting for ZAP scans to complete (seconds)
ZAP_SCAN_TIMEOUT = int(os.environ.get("ZAP_SCAN_TIMEOUT", "600"))  # 10 minutes
ZAP_POLL_INTERVAL = 5  # seconds between progress checks

# ZAP risk levels -> VibeCrack severity mapping
ZAP_RISK_MAP = {
    "0": "info",       # Informational
    "1": "low",        # Low
    "2": "medium",     # Medium
    "3": "high",       # High
}

# ZAP confidence levels
ZAP_CONFIDENCE_MAP = {
    "0": "False Positive",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Confirmed",
}


class ZAPScanner(BaseScanner):
    """OWASP ZAP integration scanner.

    By default runs passive scan only (spider + passive analysis).
    Active scanning is only performed when explicitly requested via
    the scan options (``zapActiveScan: true`` in the Firestore scan
    document or ``active_scan=True`` constructor parameter).  This
    makes ZAP safe to include in every scan without risking
    destructive active-scan payloads.
    """

    scanner_name = "zap_scanner"

    def __init__(self, scan_id: str, project_id: str, domain: str, **kwargs) -> None:
        super().__init__(scan_id, project_id, domain, **kwargs)

        # Determine whether active scanning is explicitly requested.
        self._active_scan_enabled: bool = False
        try:
            if self._data_store:
                scan_opts = self._data_store.get_scan_data(scan_id)
            else:
                from engine.orchestrator import firebase_client as _fb
                _fb._ensure_db()
                doc = _fb.db.collection("scans").document(scan_id).get()
                scan_opts = doc.to_dict() if doc.exists else {}
            self._active_scan_enabled = bool(
                scan_opts.get("zapActiveScan", False)
                or scan_opts.get("options", {}).get("zapActiveScan", False)
            )
        except Exception:
            self._active_scan_enabled = False

    def run(self) -> None:
        scan_mode = "active + passive" if self._active_scan_enabled else "passive only"
        self.log("info", f"Starting OWASP ZAP scan for {self.base_url} (mode: {scan_mode})")

        # Check if ZAP is reachable
        if not self._is_zap_available():
            self.log("warning", "OWASP ZAP is not available - skipping ZAP scan")
            self.add_finding(
                severity="info",
                title="OWASP ZAP scan not available",
                description="The OWASP ZAP container is not accessible. "
                            "ZAP scan was skipped. Run via Docker Compose to enable.",
                remediation="Start ZAP with: docker-compose up -d zap",
                affected_url=self.base_url,
            )
            return

        try:
            # 1. Spider the target to discover pages
            self.log("info", "Phase 1: Spidering target to discover pages")
            self._run_spider()

            # 2. Run passive scan (happens automatically during spider)
            self.log("info", "Phase 2: Waiting for passive scan to complete")
            self._wait_for_passive_scan()

            # 3. Active scan - only if explicitly requested
            if self._active_scan_enabled:
                self.log("info", "Phase 3: Active scan starting (explicitly requested)")
                self._run_active_scan()
            else:
                self.log("info", "Phase 3: Active scan SKIPPED (passive-only mode, set zapActiveScan=true to enable)")

            # 4. Get and import alerts
            self.log("info", "Phase 4: Importing ZAP findings")
            alerts = self._get_alerts()
            self._import_alerts(alerts)

            self.log("info", f"ZAP scan complete ({scan_mode}). Imported {len(alerts)} alert(s).")

        except Exception as e:
            self.log("error", f"ZAP scan failed: {e}")

    def _is_zap_available(self) -> bool:
        """Check if ZAP API is reachable."""
        try:
            resp = requests.get(
                f"{ZAP_API_URL}/JSON/core/view/version/",
                params={"apikey": ZAP_API_KEY},
                timeout=10,
            )
            if resp.status_code == 200:
                version = resp.json().get("version", "unknown")
                self.log("info", f"ZAP version: {version}")
                return True
        except (requests.ConnectionError, requests.Timeout):
            pass
        return False

    def _zap_api(self, path: str, params: Optional[dict] = None) -> dict:
        """Make a request to the ZAP API."""
        params = params or {}
        if ZAP_API_KEY:
            params["apikey"] = ZAP_API_KEY

        resp = requests.get(
            f"{ZAP_API_URL}{path}",
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def _run_spider(self) -> None:
        """Run ZAP's spider to crawl the target."""
        result = self._zap_api("/JSON/spider/action/scan/", {
            "url": self.base_url,
            "maxChildren": "50",
            "recurse": "true",
            "subtreeOnly": "true",
        })
        scan_id = result.get("scan", "0")

        # Wait for spider to complete
        elapsed = 0
        while elapsed < ZAP_SCAN_TIMEOUT:
            status = self._zap_api("/JSON/spider/view/status/", {"scanId": scan_id})
            progress = int(status.get("status", "0"))

            if progress >= 100:
                break

            self.log("info", f"Spider progress: {progress}%")
            time.sleep(ZAP_POLL_INTERVAL)
            elapsed += ZAP_POLL_INTERVAL

        # Get spider results
        results = self._zap_api("/JSON/spider/view/results/", {"scanId": scan_id})
        urls_found = len(results.get("results", []))
        self.log("info", f"Spider complete. Found {urls_found} URL(s).")

    def _wait_for_passive_scan(self) -> None:
        """Wait for ZAP's passive scanner to finish processing."""
        elapsed = 0
        while elapsed < 60:
            status = self._zap_api("/JSON/pscan/view/recordsToScan/")
            remaining = int(status.get("recordsToScan", "0"))
            if remaining == 0:
                break
            time.sleep(2)
            elapsed += 2

    def _run_active_scan(self) -> None:
        """Run ZAP's active scanner against the target."""
        result = self._zap_api("/JSON/ascan/action/scan/", {
            "url": self.base_url,
            "recurse": "true",
            "subtreeOnly": "true",
            "scanPolicyName": "",
        })
        scan_id = result.get("scan", "0")

        # Wait for active scan to complete
        elapsed = 0
        while elapsed < ZAP_SCAN_TIMEOUT:
            status = self._zap_api("/JSON/ascan/view/status/", {"scanId": scan_id})
            progress = int(status.get("status", "0"))

            if progress >= 100:
                break

            self.log("info", f"Active scan progress: {progress}%")
            time.sleep(ZAP_POLL_INTERVAL)
            elapsed += ZAP_POLL_INTERVAL

    def _get_alerts(self) -> list[dict[str, Any]]:
        """Get all alerts from ZAP for the target."""
        result = self._zap_api("/JSON/alert/view/alerts/", {
            "baseurl": self.base_url,
            "start": "0",
            "count": "500",
        })
        return result.get("alerts", [])

    def _import_alerts(self, alerts: list[dict[str, Any]]) -> None:
        """Convert ZAP alerts into VibeCrack findings."""
        seen_titles: set[str] = set()

        for alert in alerts:
            title = alert.get("name", alert.get("alert", "Unknown ZAP Alert"))

            # Skip duplicates (ZAP may report same alert for multiple URLs)
            if title in seen_titles:
                continue
            seen_titles.add(title)

            risk = str(alert.get("risk", "0"))
            severity = ZAP_RISK_MAP.get(risk, "info")

            confidence = str(alert.get("confidence", "0"))
            confidence_label = ZAP_CONFIDENCE_MAP.get(confidence, "Unknown")

            # Skip low-confidence informational alerts
            if severity == "info" and confidence in ("0", "1"):
                continue

            description = alert.get("description", "")
            solution = alert.get("solution", "")
            evidence = alert.get("evidence", "")
            url = alert.get("url", self.base_url)
            cwe_id = alert.get("cweid", "")
            wasc_id = alert.get("wascid", "")

            # Build OWASP category from CWE if available
            owasp = ""
            if cwe_id:
                owasp = f"CWE-{cwe_id}"

            self.add_finding(
                severity=severity,
                title=f"[ZAP] {title}",
                description=(
                    f"{description}\n\n"
                    f"Confidence: {confidence_label} | "
                    f"CWE: {cwe_id or 'N/A'} | WASC: {wasc_id or 'N/A'}"
                ),
                evidence=evidence[:500] if evidence else "",
                remediation=solution or "Refer to the OWASP ZAP documentation for details.",
                owasp_category=owasp,
                cvss_score=self._risk_to_cvss(risk),
                affected_url=url,
            )

    @staticmethod
    def _risk_to_cvss(risk: str) -> float:
        """Map ZAP risk level to approximate CVSS score."""
        return {
            "0": 0.0,
            "1": 3.0,
            "2": 5.5,
            "3": 8.0,
        }.get(risk, 0.0)
