"""
HackerPA Engine - Cloud Run HTTP Handler

Receives CloudEvents from Eventarc when a new scan document is created
in Firestore, then runs the scan synchronously and returns.
"""

import logging
import os
import re
import sys
import traceback

from flask import Flask, Request, jsonify, request

# ---------------------------------------------------------------------------
# Logging (must be configured before importing engine modules)
# ---------------------------------------------------------------------------

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("hackerpa.cloudrun")

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Lazy-init flag so Firebase is only initialized once per container
_firebase_initialized = False


def _ensure_firebase():
    global _firebase_initialized
    if not _firebase_initialized:
        from engine.orchestrator import firebase_client
        firebase_client.initialize()
        _firebase_initialized = True


def _extract_scan_id(req: Request) -> str | None:
    """Extract scan_id from a CloudEvent delivered by Eventarc.

    Eventarc sets the header ``ce-subject`` to a value like
    ``documents/scans/<scanId>``.  We parse the scan ID from there.
    Falls back to a JSON body field ``scan_id`` for manual testing.
    """
    # CloudEvent header (Eventarc)
    ce_subject = req.headers.get("ce-subject", "")
    if ce_subject:
        m = re.search(r"documents/scans/([^/]+)", ce_subject)
        if m:
            return m.group(1)

    # Fallback: JSON body (manual / testing)
    body = req.get_json(silent=True) or {}

    # Eventarc Firestore trigger body format
    if "document" in body and "name" in body.get("document", {}):
        doc_name = body["document"]["name"]
        m = re.search(r"/scans/([^/]+)$", doc_name)
        if m:
            return m.group(1)

    return body.get("scan_id")


@app.route("/", methods=["POST"])
def handle_scan():
    """Receive a CloudEvent from Eventarc and process the scan."""
    from engine.orchestrator import firebase_client
    from engine.orchestrator.job_manager import JobManager

    _ensure_firebase()

    scan_id = _extract_scan_id(request)
    if not scan_id:
        logger.warning("No scan_id found in request")
        return jsonify({"error": "missing scan_id"}), 400

    logger.info("Received event for scan: %s", scan_id)

    # Fetch the scan document
    scan_snapshot = firebase_client.get_scan_by_id(scan_id)

    if not scan_snapshot.exists:
        logger.warning("Scan %s does not exist in Firestore", scan_id)
        return jsonify({"error": "scan not found"}), 404

    scan_data = scan_snapshot.to_dict()
    status = scan_data.get("status", "")

    # Idempotency guard: only process pending scans
    if status != "pending":
        logger.info("Scan %s has status '%s', skipping (idempotency guard)", scan_id, status)
        return jsonify({"status": "skipped", "reason": f"status is {status}"}), 200

    # Mark as running
    try:
        firebase_client.update_scan_status(scan_id, "running", progress=0)
    except Exception:
        logger.exception("Failed to claim scan %s", scan_id)
        return jsonify({"error": "failed to claim scan"}), 500

    # Run the scan synchronously
    try:
        manager = JobManager(scan_snapshot)
        manager.run()
        logger.info("Scan %s completed successfully", scan_id)
        return jsonify({"status": "completed", "scan_id": scan_id}), 200
    except Exception:
        logger.exception("Scan %s failed with error", scan_id)
        tb = traceback.format_exc()
        try:
            firebase_client.update_scan_status(scan_id, "failed")
        except Exception:
            logger.exception("Failed to mark scan %s as failed", scan_id)
        return jsonify({"error": "scan failed", "detail": tb}), 500


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint for Cloud Run."""
    return jsonify({"status": "healthy", "service": "hackerpa-engine"}), 200
