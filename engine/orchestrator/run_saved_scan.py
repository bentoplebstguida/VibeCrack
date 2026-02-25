"""
Run an existing scan document directly from Firestore.

Usage examples:
  python -m engine.orchestrator.run_saved_scan --scan-id <SCAN_ID>
  python -m engine.orchestrator.run_saved_scan --keyword bendesk --force
"""

import argparse
import logging
import sys

from engine.orchestrator import firebase_client
from engine.orchestrator.job_manager import JobManager


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("hackerpa.run_saved_scan")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an existing scan from Firestore."
    )
    parser.add_argument(
        "--scan-id",
        help="Exact Firestore scan document id to execute.",
    )
    parser.add_argument(
        "--keyword",
        default="bendesk",
        help="Domain keyword used when --scan-id is not provided.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=200,
        help="How many latest scans to inspect when searching by keyword.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="If set, reset status to pending when the selected scan is not pending.",
    )
    return parser.parse_args()


def _select_scan_by_keyword(keyword: str, limit: int):
    keyword_l = keyword.lower()
    rows = list(
        firebase_client.db.collection("scans")
        .order_by("createdAt", direction="DESCENDING")
        .limit(limit)
        .stream(timeout=20)
    )

    matches = []
    for snap in rows:
        data = snap.to_dict() or {}
        domain = str(data.get("domain", "")).lower()
        if keyword_l in domain:
            matches.append(snap)

    if not matches:
        return None

    # Prefer a pending scan first, otherwise newest match.
    for snap in matches:
        status = (snap.to_dict() or {}).get("status")
        if status == "pending":
            return snap
    return matches[0]


def main() -> int:
    args = _parse_args()
    firebase_client.initialize()

    if args.scan_id:
        snap = firebase_client.get_scan_by_id(args.scan_id)
        if not snap.exists:
            logger.error("Scan %s not found.", args.scan_id)
            return 1
    else:
        snap = _select_scan_by_keyword(args.keyword, args.limit)
        if snap is None:
            logger.error(
                "No scans found for keyword '%s' in the last %d scans.",
                args.keyword,
                args.limit,
            )
            return 1

    scan_id = snap.id
    scan_data = snap.to_dict() or {}
    status = scan_data.get("status")
    domain = scan_data.get("domain")

    logger.info("Selected scan: id=%s domain=%s status=%s", scan_id, domain, status)

    if status != "pending":
        if not args.force:
            logger.error(
                "Scan is not pending (status=%s). Re-run with --force to reset it.",
                status,
            )
            return 1
        firebase_client.update_scan_status(
            scan_id,
            "pending",
            progress=0,
            current_phase="initializing",
        )
        snap = firebase_client.get_scan_by_id(scan_id)
        logger.info("Status reset to pending for scan %s", scan_id)

    manager = JobManager(snap)
    manager.run()
    logger.info("Manual execution finished for scan %s", scan_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
