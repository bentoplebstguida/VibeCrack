"""
HackerPA Engine - Main Entry Point

Listens to the Firestore ``scans`` collection for documents with
status="pending", picks them up, and hands them to the JobManager.
Supports graceful shutdown via SIGINT / SIGTERM.
"""

import logging
import os
import signal
import sys
import threading
import time
from typing import Any

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("hackerpa.engine")

# ---------------------------------------------------------------------------
# Imports (after logging is configured so init messages are visible)
# ---------------------------------------------------------------------------

from engine.orchestrator import firebase_client  # noqa: E402
from engine.orchestrator.job_manager import JobManager  # noqa: E402

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

_shutdown_event = threading.Event()
_active_scans: set[str] = set()
_active_scans_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------


def _handle_signal(signum: int, _frame: Any) -> None:
    sig_name = signal.Signals(signum).name
    logger.info("Received %s -- initiating graceful shutdown...", sig_name)
    _shutdown_event.set()


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ---------------------------------------------------------------------------
# Scan processing
# ---------------------------------------------------------------------------


def _process_scan(scan_snapshot: Any) -> None:
    """Run a scan inside its own thread."""
    scan_id = scan_snapshot.id
    try:
        manager = JobManager(scan_snapshot)
        manager.run()
    except Exception:
        logger.exception("Unhandled error while processing scan %s", scan_id)
        try:
            firebase_client.update_scan_status(scan_id, "failed")
        except Exception:
            logger.exception("Failed to mark scan %s as failed in Firestore", scan_id)
    finally:
        with _active_scans_lock:
            _active_scans.discard(scan_id)


def _on_pending_scans(snapshots: list) -> None:
    """Callback invoked by the Firestore listener whenever there are
    pending scans.
    """
    for snap in snapshots:
        scan_id = snap.id
        with _active_scans_lock:
            if scan_id in _active_scans:
                continue  # Already being processed
            _active_scans.add(scan_id)

        logger.info("Picked up pending scan: %s", scan_id)

        # Immediately mark as "running" to prevent other workers from
        # picking up the same document.
        try:
            firebase_client.update_scan_status(scan_id, "running", progress=0)
        except Exception:
            logger.exception("Failed to claim scan %s", scan_id)
            with _active_scans_lock:
                _active_scans.discard(scan_id)
            continue

        thread = threading.Thread(
            target=_process_scan,
            args=(snap,),
            name=f"scan-{scan_id}",
            daemon=True,
        )
        thread.start()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def main() -> None:
    logger.info("=== HackerPA Scan Engine starting ===")

    # 1. Initialize Firebase
    firebase_client.initialize()

    # 2. Start real-time listener for pending scans
    watcher = firebase_client.listen_for_pending_scans(_on_pending_scans)

    logger.info("Engine is running. Waiting for scans...")

    # 3. Block until shutdown signal
    try:
        while not _shutdown_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    # 4. Graceful shutdown
    logger.info("Shutting down...")
    watcher.unsubscribe()

    # Wait a moment for active threads to finish
    logger.info("Waiting for active scans to finish...")
    deadline = time.time() + 30  # 30-second grace period
    while time.time() < deadline:
        with _active_scans_lock:
            if not _active_scans:
                break
        time.sleep(1)

    with _active_scans_lock:
        if _active_scans:
            logger.warning(
                "Shutting down with %d scan(s) still active: %s",
                len(_active_scans),
                _active_scans,
            )

    logger.info("=== HackerPA Scan Engine stopped ===")


if __name__ == "__main__":
    from engine.config import RUN_MODE

    if RUN_MODE == "cloudrun":
        # Cloud Run mode: start Flask/Gunicorn HTTP handler.
        # When running via gunicorn this block isn't reached, but this
        # allows `python -m engine.orchestrator.main` to work in cloudrun
        # mode for local testing.
        from engine.orchestrator.cloudrun_handler import app

        port = int(os.environ.get("PORT", "8080"))
        logger.info("Starting Cloud Run HTTP handler on port %d", port)
        app.run(host="0.0.0.0", port=port)
    else:
        main()
