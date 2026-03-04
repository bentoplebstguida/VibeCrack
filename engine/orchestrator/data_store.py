"""
VibeCrack Engine - DataStore Abstraction Layer

Provides an abstract interface (IDataStore) and two implementations:
- LocalDataStore: in-memory storage for CLI mode (no Firebase needed)
- FirebaseDataStore: wraps existing firebase_client for SaaS mode
"""

import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class IDataStore(ABC):
    """Abstract interface for all data operations the scan engine needs."""

    # -- Scan state ----------------------------------------------------------

    @abstractmethod
    def get_scan_data(self, scan_id: str) -> dict:
        ...

    @abstractmethod
    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        *,
        progress: Optional[int] = None,
        current_phase: Optional[str] = None,
        extra_fields: Optional[dict] = None,
    ) -> None:
        ...

    @abstractmethod
    def update_scan_progress(
        self, scan_id: str, progress: int, current_phase: str
    ) -> None:
        ...

    @abstractmethod
    def is_scan_cancelled(self, scan_id: str) -> bool:
        ...

    # -- Logging -------------------------------------------------------------

    @abstractmethod
    def add_scan_log(
        self,
        scan_id: str,
        *,
        level: str = "info",
        message: str = "",
        details: Optional[dict] = None,
        scanner: str = "",
    ) -> str:
        ...

    # -- Findings ------------------------------------------------------------

    @abstractmethod
    def add_finding(
        self,
        scan_id: str,
        *,
        severity: str,
        title: str,
        description: str,
        evidence: str = "",
        remediation: str = "",
        owasp_category: str = "",
        cvss_score: float = 0.0,
        affected_url: str = "",
        scanner: str = "",
    ) -> str:
        ...

    # -- Inter-scanner data sharing ------------------------------------------

    @abstractmethod
    def get_crawl_data(self, scan_id: str) -> dict:
        ...

    @abstractmethod
    def save_crawl_data(self, scan_id: str, crawl_data: dict) -> None:
        ...

    @abstractmethod
    def get_detected_tech(self, scan_id: str) -> list[str]:
        ...

    @abstractmethod
    def save_detected_tech(self, scan_id: str, tech_list: list[str]) -> None:
        ...

    # -- Scoring & reporting -------------------------------------------------

    @abstractmethod
    def get_vulnerabilities(self, scan_id: str) -> list[dict]:
        ...

    @abstractmethod
    def save_score(
        self, scan_id: str, project_id: str, score_data: dict
    ) -> None:
        ...

    @abstractmethod
    def get_scan_with_vulns_and_score(self, scan_id: str) -> dict:
        ...

    @abstractmethod
    def save_report(
        self, scan_id: str, report_bytes: bytes, report_type: str
    ) -> str:
        ...


# ---------------------------------------------------------------------------
# LocalDataStore -- in-memory, zero dependencies
# ---------------------------------------------------------------------------


class LocalDataStore(IDataStore):
    """In-memory data store for CLI / standalone mode.

    Stores everything in plain Python dicts and lists.  Supports optional
    callbacks so the CLI can display real-time progress.
    """

    def __init__(
        self,
        *,
        on_log: Optional[Callable] = None,
        on_finding: Optional[Callable] = None,
        on_progress: Optional[Callable] = None,
    ):
        self._scans: dict[str, dict] = {}
        self._logs: list[dict] = []
        self._findings: list[dict] = []
        self._scores: dict[str, dict] = {}
        self._report_path: Optional[str] = None

        # CLI callbacks
        self._on_log = on_log
        self._on_finding = on_finding
        self._on_progress = on_progress

    # -- Bootstrap -----------------------------------------------------------

    def create_scan(
        self,
        scan_id: str,
        domain: str,
        modules: list[str],
        scan_type: str = "full",
        project_id: str = "cli",
    ) -> None:
        """Initialize a scan record (called by the CLI entry point)."""
        self._scans[scan_id] = {
            "domain": domain,
            "modules": modules,
            "scanType": scan_type,
            "status": "pending",
            "progress": 0,
            "currentPhase": None,
            "projectId": project_id,
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "crawlData": {},
            "detectedTech": [],
            "score": None,
            "grade": None,
            "aiSummary": None,
            "exploitPlaybook": None,
            "reportUrl": None,
            "scannerResults": {},
            "createdAt": datetime.now(timezone.utc),
            "startedAt": None,
            "completedAt": None,
        }

    # -- Scan state ----------------------------------------------------------

    def get_scan_data(self, scan_id: str) -> dict:
        return dict(self._scans.get(scan_id, {}))

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        *,
        progress: Optional[int] = None,
        current_phase: Optional[str] = None,
        extra_fields: Optional[dict] = None,
    ) -> None:
        scan = self._scans.get(scan_id)
        if scan is None:
            return
        scan["status"] = status
        if progress is not None:
            scan["progress"] = progress
        if current_phase is not None:
            scan["currentPhase"] = current_phase
        if extra_fields:
            scan.update(extra_fields)

        if self._on_progress:
            self._on_progress(
                scan.get("progress", 0),
                scan.get("currentPhase", ""),
            )

    def update_scan_progress(
        self, scan_id: str, progress: int, current_phase: str
    ) -> None:
        self.update_scan_status(
            scan_id, "running", progress=progress, current_phase=current_phase
        )

    def is_scan_cancelled(self, scan_id: str) -> bool:
        scan = self._scans.get(scan_id, {})
        return scan.get("status") == "cancelled"

    # -- Logging -------------------------------------------------------------

    def add_scan_log(
        self,
        scan_id: str,
        *,
        level: str = "info",
        message: str = "",
        details: Optional[dict] = None,
        scanner: str = "",
    ) -> str:
        log_id = str(uuid.uuid4())
        entry = {
            "id": log_id,
            "scanId": scan_id,
            "level": level,
            "message": message,
            "details": details or {},
            "scanner": scanner,
            "timestamp": datetime.now(timezone.utc),
        }
        self._logs.append(entry)
        if self._on_log:
            self._on_log(level, message, scanner)
        return log_id

    # -- Findings ------------------------------------------------------------

    def add_finding(
        self,
        scan_id: str,
        *,
        severity: str,
        title: str,
        description: str,
        evidence: str = "",
        remediation: str = "",
        owasp_category: str = "",
        cvss_score: float = 0.0,
        affected_url: str = "",
        scanner: str = "",
    ) -> str:
        finding_id = str(uuid.uuid4())
        scan = self._scans.get(scan_id, {})
        project_id = scan.get("projectId", "")

        finding = {
            "id": finding_id,
            "scanId": scan_id,
            "projectId": project_id,
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": {"detail": evidence} if isinstance(evidence, str) else evidence,
            "remediation": remediation,
            "owaspCategory": owasp_category,
            "cvssScore": cvss_score,
            "affectedUrl": affected_url,
            "scanner": scanner,
            "createdAt": datetime.now(timezone.utc),
        }
        self._findings.append(finding)

        # Update summary counts
        summary = scan.get("summary", {})
        summary[severity] = summary.get(severity, 0) + 1

        if self._on_finding:
            self._on_finding(severity, title, affected_url, scanner)

        return finding_id

    # -- Inter-scanner data sharing ------------------------------------------

    def get_crawl_data(self, scan_id: str) -> dict:
        scan = self._scans.get(scan_id, {})
        return scan.get("crawlData", {})

    def save_crawl_data(self, scan_id: str, crawl_data: dict) -> None:
        scan = self._scans.get(scan_id)
        if scan:
            scan["crawlData"] = crawl_data

    def get_detected_tech(self, scan_id: str) -> list[str]:
        scan = self._scans.get(scan_id, {})
        return scan.get("detectedTech", [])

    def save_detected_tech(self, scan_id: str, tech_list: list[str]) -> None:
        scan = self._scans.get(scan_id)
        if scan:
            scan["detectedTech"] = tech_list

    # -- Scoring & reporting -------------------------------------------------

    def get_vulnerabilities(self, scan_id: str) -> list[dict]:
        return [f for f in self._findings if f.get("scanId") == scan_id]

    def save_score(
        self, scan_id: str, project_id: str, score_data: dict
    ) -> None:
        self._scores[scan_id] = score_data
        scan = self._scans.get(scan_id)
        if scan:
            scan["score"] = score_data.get("overallScore")
            scan["grade"] = score_data.get("grade")

    def get_score(self, scan_id: str) -> Optional[dict]:
        return self._scores.get(scan_id)

    def get_scan_with_vulns_and_score(self, scan_id: str) -> dict:
        scan = self.get_scan_data(scan_id)
        scan["vulnerabilities"] = self.get_vulnerabilities(scan_id)
        scan["score_data"] = self._scores.get(scan_id, {})
        return scan

    def save_report(
        self, scan_id: str, report_bytes: bytes, report_type: str
    ) -> str:
        """Save report to local file. Returns the file path."""
        import os

        scan = self._scans.get(scan_id, {})
        domain = scan.get("domain", "scan")
        safe_domain = domain.replace("https://", "").replace("http://", "").replace("/", "_")
        filename = f"vibecrack_{safe_domain}_{report_type}.pdf"
        with open(filename, "wb") as f:
            f.write(report_bytes)
        self._report_path = os.path.abspath(filename)
        return self._report_path

    # -- Accessors for CLI output -------------------------------------------

    def get_logs(self, scan_id: str) -> list[dict]:
        return [log for log in self._logs if log.get("scanId") == scan_id]


# ---------------------------------------------------------------------------
# FirebaseDataStore -- wraps existing firebase_client for backward compat
# ---------------------------------------------------------------------------


class FirebaseDataStore(IDataStore):
    """Wraps the existing firebase_client module for SaaS mode.

    All methods delegate to the already-proven firebase_client functions,
    ensuring zero behavioral change for production.
    """

    def __init__(self):
        from engine.orchestrator import firebase_client

        firebase_client.initialize()
        self._fb = firebase_client

    def get_scan_data(self, scan_id: str) -> dict:
        doc = self._fb.get_scan_by_id(scan_id)
        return doc.to_dict() if doc.exists else {}

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        *,
        progress: Optional[int] = None,
        current_phase: Optional[str] = None,
        extra_fields: Optional[dict] = None,
    ) -> None:
        self._fb.update_scan_status(
            scan_id,
            status,
            progress=progress,
            current_phase=current_phase,
            extra_fields=extra_fields,
        )

    def update_scan_progress(
        self, scan_id: str, progress: int, current_phase: str
    ) -> None:
        self._fb.update_scan_progress(scan_id, progress, current_phase)

    def is_scan_cancelled(self, scan_id: str) -> bool:
        try:
            doc = self._fb.db.collection("scans").document(scan_id).get()
            if doc.exists:
                return doc.to_dict().get("status") == "cancelled"
        except Exception:
            pass
        return False

    def add_scan_log(
        self,
        scan_id: str,
        *,
        level: str = "info",
        message: str = "",
        details: Optional[dict] = None,
        scanner: str = "",
    ) -> str:
        return self._fb.add_scan_log(
            scan_id, level=level, message=message, details=details, scanner=scanner
        )

    def add_finding(
        self,
        scan_id: str,
        *,
        severity: str,
        title: str,
        description: str,
        evidence: str = "",
        remediation: str = "",
        owasp_category: str = "",
        cvss_score: float = 0.0,
        affected_url: str = "",
        scanner: str = "",
    ) -> str:
        return self._fb.add_finding(
            scan_id,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            remediation=remediation,
            owasp_category=owasp_category,
            cvss_score=cvss_score,
            affected_url=affected_url,
            scanner=scanner,
        )

    def get_crawl_data(self, scan_id: str) -> dict:
        return self._fb.get_crawl_data(scan_id)

    def save_crawl_data(self, scan_id: str, crawl_data: dict) -> None:
        self._fb.update_scan_status(
            scan_id, "running", extra_fields={"crawlData": crawl_data}
        )

    def get_detected_tech(self, scan_id: str) -> list[str]:
        return self._fb.get_detected_tech(scan_id)

    def save_detected_tech(self, scan_id: str, tech_list: list[str]) -> None:
        self._fb.save_detected_tech(scan_id, tech_list)

    def get_vulnerabilities(self, scan_id: str) -> list[dict]:
        self._fb._ensure_db()
        docs = list(
            self._fb.db.collection("vulnerabilities")
            .where("scanId", "==", scan_id)
            .stream()
        )
        return [doc.to_dict() for doc in docs]

    def save_score(
        self, scan_id: str, project_id: str, score_data: dict
    ) -> None:
        self._fb._ensure_db()
        db = self._fb.db

        db.collection("scores_history").add(
            {
                "projectId": project_id,
                "scanId": scan_id,
                "overallScore": score_data["overallScore"],
                "grade": score_data["grade"],
                "categories": score_data["categories"],
                "createdAt": datetime.now(timezone.utc),
            }
        )

        db.collection("scans").document(scan_id).update(
            {"score": score_data["overallScore"], "grade": score_data["grade"]}
        )

        if project_id:
            from google.cloud.firestore_v1 import transforms

            db.collection("projects").document(project_id).update(
                {
                    "currentScore": score_data["overallScore"],
                    "currentGrade": score_data["grade"],
                    "lastScanAt": datetime.now(timezone.utc),
                    "totalScans": transforms.Increment(1),
                }
            )

    def get_scan_with_vulns_and_score(self, scan_id: str) -> dict:
        scan = self.get_scan_data(scan_id)
        scan["vulnerabilities"] = self.get_vulnerabilities(scan_id)
        return scan

    def save_report(
        self, scan_id: str, report_bytes: bytes, report_type: str
    ) -> str:
        from firebase_admin import storage as fb_storage

        bucket = fb_storage.bucket()
        blob = bucket.blob(f"reports/{scan_id}/{report_type}.pdf")
        blob.upload_from_string(report_bytes, content_type="application/pdf")
        blob.make_public()
        url = blob.public_url

        self._fb.update_scan_status(
            scan_id, "running", extra_fields={"reportUrl": url}
        )
        return url


class ScanSnapshot:
    """Mimics a Firestore DocumentSnapshot for CLI use with JobManager."""

    def __init__(self, scan_id: str, data: dict):
        self.id = scan_id
        self._data = data

    def to_dict(self) -> dict:
        return dict(self._data)
