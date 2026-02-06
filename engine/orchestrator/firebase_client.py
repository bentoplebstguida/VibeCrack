"""
HackerPA Engine - Firebase Admin SDK Client

Initializes the Firebase Admin SDK and provides helper functions
for interacting with Firestore (scans, findings, logs).
"""

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from engine.config import FIREBASE_CREDENTIALS_PATH

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Firebase Initialization
# ---------------------------------------------------------------------------

_app: Optional[firebase_admin.App] = None
db: Optional[firestore.firestore.Client] = None


def initialize() -> firestore.firestore.Client:
    """Initialize the Firebase Admin SDK and return the Firestore client.

    Can be called multiple times safely; only the first call has an effect.
    """
    global _app, db

    if _app is not None and db is not None:
        return db

    try:
        cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
        _app = firebase_admin.initialize_app(cred)
        db = firestore.client()
        logger.info("Firebase Admin SDK initialized successfully.")
    except ValueError:
        # App already initialized (e.g. in tests)
        _app = firebase_admin.get_app()
        db = firestore.client()
        logger.info("Reusing existing Firebase app.")

    return db


# ---------------------------------------------------------------------------
# Scan helpers
# ---------------------------------------------------------------------------


def listen_for_pending_scans(callback: Callable[[list], None]) -> Any:
    """Create a real-time listener on the `scans` collection for documents
    whose status equals ``"pending"``.

    ``callback`` receives a list of document snapshots each time there is
    a change.  Returns the watcher object so the caller can call
    ``.unsubscribe()`` to stop listening.
    """
    _ensure_db()

    query = (
        db.collection("scans")
        .where(filter=FieldFilter("status", "==", "pending"))
    )

    def _on_snapshot(doc_snapshots, changes, read_time):
        """Firestore on_snapshot callback."""
        if doc_snapshots:
            callback(doc_snapshots)

    watcher = query.on_snapshot(_on_snapshot)
    logger.info("Listening for pending scans in Firestore...")
    return watcher


def get_pending_scans() -> list:
    """One-shot query: return all scan documents with status='pending'."""
    _ensure_db()

    query = (
        db.collection("scans")
        .where(filter=FieldFilter("status", "==", "pending"))
        .order_by("createdAt")
    )
    return list(query.stream())


# ---------------------------------------------------------------------------
# Scan status / progress
# ---------------------------------------------------------------------------


def update_scan_status(
    scan_id: str,
    status: str,
    *,
    progress: Optional[int] = None,
    current_phase: Optional[str] = None,
    extra_fields: Optional[dict] = None,
) -> None:
    """Update the status (and optionally progress / phase) of a scan document."""
    _ensure_db()

    data: dict[str, Any] = {
        "status": status,
        "updatedAt": _now(),
    }
    if progress is not None:
        data["progress"] = progress
    if current_phase is not None:
        data["currentPhase"] = current_phase
    if extra_fields:
        data.update(extra_fields)

    db.collection("scans").document(scan_id).update(data)
    logger.debug("Scan %s status -> %s (progress=%s, phase=%s)",
                 scan_id, status, progress, current_phase)


def update_scan_progress(scan_id: str, progress: int, current_phase: str) -> None:
    """Convenience wrapper to update only progress and phase."""
    update_scan_status(
        scan_id, "running", progress=progress, current_phase=current_phase
    )


# ---------------------------------------------------------------------------
# Vulnerability findings
# ---------------------------------------------------------------------------


def add_finding(
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
    """Add a vulnerability finding to the ``vulnerabilities`` sub-collection
    of the given scan.  Returns the new document ID.
    """
    _ensure_db()

    # Get projectId from the scan document
    scan_doc = db.collection("scans").document(scan_id).get()
    project_id = scan_doc.to_dict().get("projectId", "") if scan_doc.exists else ""

    doc_ref = db.collection("vulnerabilities").document()

    doc_ref.set({
        "scanId": scan_id,
        "projectId": project_id,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence if isinstance(evidence, dict) else {"detail": evidence},
        "remediation": remediation,
        "owaspCategory": owasp_category,
        "cvssScore": cvss_score,
        "affectedUrl": affected_url,
        "scanner": scanner,
        "createdAt": _now(),
    })

    # Update scan summary counts
    _increment_scan_summary(scan_id, severity)

    logger.debug("Finding added to scan %s: %s (%s)", scan_id, title, severity)
    return doc_ref.id


# ---------------------------------------------------------------------------
# Scan logs
# ---------------------------------------------------------------------------


def add_scan_log(
    scan_id: str,
    *,
    level: str = "info",
    message: str = "",
    details: Optional[dict] = None,
    scanner: str = "",
) -> str:
    """Append a log entry to the ``scan_logs`` sub-collection of the given
    scan.  Returns the new document ID.
    """
    _ensure_db()

    doc_ref = db.collection("scan_logs").document()

    doc_ref.set({
        "scanId": scan_id,
        "level": level,
        "message": message,
        "details": details or {},
        "scanner": scanner,
        "timestamp": _now(),
    })

    logger.debug("Log [%s] scan %s: %s", level, scan_id, message)
    return doc_ref.id


# ---------------------------------------------------------------------------
# Detected technologies (shared between scanners)
# ---------------------------------------------------------------------------


def save_detected_tech(scan_id: str, tech_list: list[str]) -> None:
    """Save detected technologies to the scan document so subsequent
    scanners can use them for framework-specific remediation."""
    _ensure_db()
    db.collection("scans").document(scan_id).update({
        "detectedTech": tech_list,
    })


def get_detected_tech(scan_id: str) -> list[str]:
    """Load detected technologies from the scan document."""
    _ensure_db()
    doc = db.collection("scans").document(scan_id).get()
    if doc.exists:
        return doc.to_dict().get("detectedTech", [])
    return []


def get_crawl_data(scan_id: str) -> dict:
    """Load crawl data from a scan document."""
    _ensure_db()
    doc = db.collection("scans").document(scan_id).get()
    if doc.exists:
        return doc.to_dict().get("crawlData", {})
    return {}


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------


def _increment_scan_summary(scan_id: str, severity: str) -> None:
    """Increment the summary counter for the given severity on the scan doc."""
    _ensure_db()
    from google.cloud.firestore_v1 import transforms
    field = f"summary.{severity}"
    db.collection("scans").document(scan_id).update({
        field: transforms.Increment(1),
    })


def _ensure_db() -> None:
    """Raise if the SDK has not been initialized yet."""
    if db is None:
        raise RuntimeError(
            "Firebase has not been initialized. Call firebase_client.initialize() first."
        )


def _now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)
