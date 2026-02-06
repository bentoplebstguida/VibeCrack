"""
HackerPA Engine - Score Calculator

Computes the overall security score (0-100) and per-category sub-scores
based on the vulnerabilities found during a scan. Also saves score history
and updates the project's current score.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from engine.orchestrator import firebase_client

logger = logging.getLogger(__name__)

# Penalty points per severity level
SEVERITY_PENALTIES = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

# Scanner -> Category mapping
SCANNER_CATEGORY_MAP = {
    "ssl_scanner": "ssl_tls",
    "headers_scanner": "headers",
    "xss_scanner": "injection",
    "sqli_scanner": "injection",
    "csrf_scanner": "injection",
    "secrets_scanner": "secrets_exposure",
    "directory_scanner": "configuration",
    "endpoint_scanner": "authentication",
    "recon_scanner": "information_disclosure",
    "zap_scanner": "injection",
}

# Category weights (must sum to 100)
CATEGORY_WEIGHTS = {
    "ssl_tls": 15,
    "headers": 15,
    "injection": 20,
    "authentication": 15,
    "secrets_exposure": 15,
    "configuration": 10,
    "information_disclosure": 10,
}


def score_to_grade(score: int) -> str:
    """Convert numeric score to letter grade."""
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 70:
        return "B"
    if score >= 50:
        return "C"
    if score >= 30:
        return "D"
    return "F"


def calculate(scan_id: str) -> dict[str, Any]:
    """Calculate the security score for a completed scan.

    Reads all vulnerabilities for the scan, computes per-category
    scores, an overall weighted score, and saves everything to
    Firestore (scores_history collection + updates scan and project docs).
    """
    firebase_client._ensure_db()
    db = firebase_client.db

    # 1. Get scan document
    scan_ref = db.collection("scans").document(scan_id)
    scan_doc = scan_ref.get()
    if not scan_doc.exists:
        raise ValueError(f"Scan {scan_id} not found")

    scan_data = scan_doc.to_dict()
    project_id = scan_data.get("projectId", "")

    # 2. Get all vulnerabilities for this scan
    vulns = list(
        db.collection("vulnerabilities")
        .where("scanId", "==", scan_id)
        .stream()
    )

    # 3. Compute per-category scores
    category_findings: dict[str, list[str]] = {cat: [] for cat in CATEGORY_WEIGHTS}

    for vuln_doc in vulns:
        vuln = vuln_doc.to_dict()
        scanner = vuln.get("scanner", "")
        severity = vuln.get("severity", "info")
        category = SCANNER_CATEGORY_MAP.get(scanner, "configuration")
        category_findings[category].append(severity)

    category_scores: dict[str, dict[str, Any]] = {}
    for category, weight in CATEGORY_WEIGHTS.items():
        findings = category_findings[category]
        cat_score = 100
        for sev in findings:
            penalty = SEVERITY_PENALTIES.get(sev, 0)
            cat_score -= penalty
        cat_score = max(0, min(100, cat_score))

        category_scores[category] = {
            "score": cat_score,
            "grade": score_to_grade(cat_score),
            "weight": weight,
        }

    # 4. Compute overall weighted score
    overall_score = 0
    for category, data in category_scores.items():
        overall_score += data["score"] * (data["weight"] / 100)
    overall_score = max(0, min(100, round(overall_score)))
    overall_grade = score_to_grade(overall_score)

    logger.info(
        "Scan %s score: %d (%s) - categories: %s",
        scan_id,
        overall_score,
        overall_grade,
        {k: v["score"] for k, v in category_scores.items()},
    )

    # 5. Save score history
    db.collection("scores_history").add({
        "projectId": project_id,
        "scanId": scan_id,
        "overallScore": overall_score,
        "grade": overall_grade,
        "categories": category_scores,
        "createdAt": datetime.now(timezone.utc),
    })

    # 6. Update scan document with score
    scan_ref.update({
        "score": overall_score,
        "grade": overall_grade,
    })

    # 7. Update project with current score
    if project_id:
        from google.cloud.firestore_v1 import transforms
        db.collection("projects").document(project_id).update({
            "currentScore": overall_score,
            "currentGrade": overall_grade,
            "lastScanAt": datetime.now(timezone.utc),
            "totalScans": transforms.Increment(1),
        })

    return {
        "overallScore": overall_score,
        "grade": overall_grade,
        "categories": category_scores,
    }
