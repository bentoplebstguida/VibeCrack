"""
HackerPA Engine - Job Manager

Orchestrates the execution of scanner modules for a single scan job.
Each scanner runs sequentially; a failure in one scanner does not prevent
the remaining scanners from executing.
"""

import importlib
import logging
import traceback
from typing import Any

from engine.orchestrator import firebase_client

logger = logging.getLogger(__name__)

# Maps logical module names (as stored in the scan document) to their
# fully-qualified Python module paths and class names.
SCANNER_REGISTRY: dict[str, dict[str, str]] = {
    "recon": {
        "module": "engine.scanners.recon_scanner",
        "class": "ReconScanner",
    },
    "subdomains": {
        "module": "engine.scanners.subdomain_scanner",
        "class": "SubdomainScanner",
    },
    "ssl": {
        "module": "engine.scanners.ssl_scanner",
        "class": "SSLScanner",
    },
    "headers": {
        "module": "engine.scanners.headers_scanner",
        "class": "HeadersScanner",
    },
    "secrets": {
        "module": "engine.scanners.secrets_scanner",
        "class": "SecretsScanner",
    },
    "directories": {
        "module": "engine.scanners.directory_scanner",
        "class": "DirectoryScanner",
    },
    "xss": {
        "module": "engine.scanners.xss_scanner",
        "class": "XSSScanner",
    },
    "sqli": {
        "module": "engine.scanners.sqli_scanner",
        "class": "SQLiScanner",
    },
    "csrf": {
        "module": "engine.scanners.csrf_scanner",
        "class": "CSRFScanner",
    },
    "endpoints": {
        "module": "engine.scanners.endpoint_scanner",
        "class": "EndpointScanner",
    },
    "ssrf": {
        "module": "engine.scanners.ssrf_scanner",
        "class": "SSRFScanner",
    },
    "zap": {
        "module": "engine.scanners.zap_scanner",
        "class": "ZAPScanner",
    },
    "crawler": {
        "module": "engine.scanners.crawler",
        "class": "CrawlerScanner",
    },
    "access_control": {
        "module": "engine.scanners.access_control_scanner",
        "class": "AccessControlScanner",
    },
    "xss_browser": {
        "module": "engine.scanners.xss_browser_scanner",
        "class": "XSSBrowserScanner",
    },
}


class JobManager:
    """Manages the lifecycle of a single scan job.

    Parameters
    ----------
    scan_snapshot : google.cloud.firestore_v1.document.DocumentSnapshot
        The Firestore document snapshot for the scan.
    """

    def __init__(self, scan_snapshot: Any, *, data_store=None) -> None:
        self.scan_id: str = scan_snapshot.id
        self.scan_data: dict[str, Any] = scan_snapshot.to_dict()
        self.domain: str = self.scan_data.get("domain", "")
        self.project_id: str = self.scan_data.get("projectId", "")
        self.modules: list[str] = self.scan_data.get("modules", [])
        self.data_store = data_store  # None = legacy firebase_client path

        # Track per-module results
        self.results: dict[str, str] = {}  # module_name -> "success" | "error"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    # -- DataStore helpers (dual-path) --------------------------------------

    def _update_status(self, status, *, progress=None, current_phase=None, extra_fields=None):
        if self.data_store:
            self.data_store.update_scan_status(
                self.scan_id, status,
                progress=progress, current_phase=current_phase,
                extra_fields=extra_fields,
            )
        else:
            firebase_client.update_scan_status(
                self.scan_id, status,
                progress=progress, current_phase=current_phase,
                extra_fields=extra_fields,
            )

    def _update_progress(self, progress, current_phase):
        if self.data_store:
            self.data_store.update_scan_progress(self.scan_id, progress, current_phase)
        else:
            firebase_client.update_scan_progress(self.scan_id, progress, current_phase)

    def _add_log(self, *, level="info", message="", details=None, scanner=""):
        if self.data_store:
            self.data_store.add_scan_log(
                self.scan_id, level=level, message=message,
                details=details, scanner=scanner,
            )
        else:
            firebase_client.add_scan_log(
                self.scan_id, level=level, message=message,
                details=details, scanner=scanner,
            )

    # -- Public API ----------------------------------------------------------

    def run(self) -> None:
        """Execute all requested scanner modules sequentially, update
        progress as we go, and finalise the scan.
        """
        logger.info(
            "Starting scan %s for domain %s (modules: %s)",
            self.scan_id,
            self.domain,
            self.modules,
        )

        # Mark scan as running
        self._update_status("running", progress=0, current_phase="initializing")
        self._add_log(
            level="info",
            message=f"Scan started for {self.domain}",
            details={"modules": self.modules},
        )

        total = len(self.modules) if self.modules else 1
        completed = 0
        had_errors = False

        for module_name in self.modules:
            # Check if scan was cancelled by the user
            if self._is_cancelled():
                logger.info("Scan %s was cancelled by user", self.scan_id)
                self._add_log(level="info", message="Scan cancelado pelo usuario")
                self._update_status(
                    "cancelled",
                    progress=self._progress(completed, total),
                    current_phase="cancelled",
                )
                return

            try:
                self._run_scanner(module_name, completed, total)
                self.results[module_name] = "success"
            except Exception:
                had_errors = True
                self.results[module_name] = "error"
                tb = traceback.format_exc()
                logger.error(
                    "Scanner %s failed for scan %s:\n%s",
                    module_name,
                    self.scan_id,
                    tb,
                )
                self._add_log(
                    level="error",
                    message=f"Scanner '{module_name}' failed",
                    details={"traceback": tb},
                    scanner=module_name,
                )
            finally:
                completed += 1
                progress = int((completed / total) * 100)
                self._update_progress(min(progress, 95), module_name)

        # ---- Post-scan: calculate score ----
        self._calculate_score()

        # ---- Post-scan: generate PDF report ----
        self._generate_report()

        # ---- Post-scan: AI analysis (Claude API) ----
        self._generate_ai_analysis()

        # ---- Finalise ----
        from datetime import datetime, timezone
        final_status = "completed" if not had_errors else "completed"
        # Only mark as "failed" if ALL scanners errored out
        if had_errors and all(v == "error" for v in self.results.values()):
            final_status = "failed"

        self._update_status(
            final_status,
            progress=100,
            current_phase="done",
            extra_fields={
                "completedAt": datetime.now(timezone.utc),
                "scannerResults": self.results,
            },
        )
        self._add_log(
            level="info",
            message=f"Scan finished with status: {final_status}",
            details={"results": self.results},
        )

        logger.info("Scan %s finished with status: %s", self.scan_id, final_status)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_cancelled(self) -> bool:
        """Check if the scan status was set to 'cancelled'."""
        if self.data_store:
            return self.data_store.is_scan_cancelled(self.scan_id)
        try:
            doc = firebase_client.db.collection("scans").document(self.scan_id).get()
            if doc.exists:
                return doc.to_dict().get("status") == "cancelled"
        except Exception:
            pass
        return False

    @staticmethod
    def _progress(completed: int, total: int) -> int:
        return min(int((completed / total) * 100), 95) if total else 0

    def _run_scanner(self, module_name: str, completed: int, total: int) -> None:
        """Dynamically import and run a single scanner module."""
        registry_entry = SCANNER_REGISTRY.get(module_name)
        if registry_entry is None:
            raise ValueError(f"Unknown scanner module: {module_name}")

        logger.info("Running scanner: %s (%d/%d)", module_name, completed + 1, total)
        self._update_progress(int((completed / total) * 100), module_name)
        self._add_log(
            level="info",
            message=f"Starting scanner: {module_name}",
            scanner=module_name,
        )

        # Dynamic import
        mod = importlib.import_module(registry_entry["module"])
        scanner_cls = getattr(mod, registry_entry["class"])

        # Instantiate and run (pass data_store to scanner)
        scanner_instance = scanner_cls(
            scan_id=self.scan_id,
            project_id=self.project_id,
            domain=self.domain,
            data_store=self.data_store,
        )
        scanner_instance.run()

        self._add_log(
            level="info",
            message=f"Scanner '{module_name}' completed successfully",
            scanner=module_name,
        )

    def _calculate_score(self) -> None:
        """Trigger the scoring module to compute an overall security score."""
        self._update_progress(98, "scoring")
        self._add_log(level="info", message="Calculating security score")

        try:
            from engine.scoring.calculator import calculate, calculate_local
            if self.data_store:
                calculate_local(self.scan_id, self.project_id, self.data_store)
            else:
                calculate(self.scan_id)
        except Exception:
            tb = traceback.format_exc()
            logger.error(
                "Score calculation failed for scan %s:\n%s", self.scan_id, tb
            )
            self._add_log(
                level="error",
                message="Score calculation failed",
                details={"traceback": tb},
            )

    def _generate_ai_analysis(self) -> None:
        """Use Claude API to generate AI analysis and exploit playbook."""
        import os

        if not os.environ.get("ANTHROPIC_API_KEY"):
            logger.info("ANTHROPIC_API_KEY not set, skipping AI analysis")
            return

        self._update_progress(99, "ai_analysis")
        self._add_log(level="info", message="Generating AI analysis with Claude")

        try:
            from engine.reporting.ai_analyzer import generate_ai_analysis
            result = generate_ai_analysis(self.scan_id, data_store=self.data_store)
            self._update_status(
                "running",
                extra_fields={
                    "aiSummary": result["aiSummary"],
                    "exploitPlaybook": result["exploitPlaybook"],
                },
            )
            self._add_log(level="info", message="AI analysis generated successfully")
        except Exception:
            tb = traceback.format_exc()
            logger.error(
                "AI analysis failed for scan %s:\n%s", self.scan_id, tb
            )
            self._add_log(
                level="warning",
                message="AI analysis failed (non-critical)",
                details={"traceback": tb},
            )

    def _generate_report(self) -> None:
        """Generate PDF report and upload/save."""
        self._update_progress(99, "reporting")
        self._add_log(level="info", message="Generating PDF report")

        try:
            from engine.reporting.pdf_generator import generate_and_upload
            report_url = generate_and_upload(
                self.scan_id, report_type="full", data_store=self.data_store
            )
            self._update_status(
                "running", extra_fields={"reportUrl": report_url}
            )
            self._add_log(
                level="info", message=f"PDF report generated: {report_url}"
            )
        except Exception:
            tb = traceback.format_exc()
            logger.error(
                "PDF generation failed for scan %s:\n%s", self.scan_id, tb
            )
            self._add_log(
                level="warning",
                message="PDF report generation failed (non-critical)",
                details={"traceback": tb},
            )
