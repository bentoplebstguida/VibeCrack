"""
VibeCrack CLI - Open Source Security Scanner

Usage:
    vibecrack https://example.com
    vibecrack https://example.com --modules ssl,headers,xss,sqli
    vibecrack https://example.com --quick
    vibecrack https://example.com --json results.json --html report.html
"""

import argparse
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Module sets
# ---------------------------------------------------------------------------

QUICK_MODULES = ["crawler", "recon", "ssl", "headers"]

FULL_MODULES = [
    "crawler",
    "recon",
    "subdomains",
    "ssl",
    "headers",
    "secrets",
    "directories",
    "xss",
    "sqli",
    "csrf",
    "endpoints",
    "access_control",
]

# Modules that need optional heavy dependencies
_OPTIONAL_DEP_MODULES = {
    "xss_browser": "playwright",
    "zap": "python-owasp-zap-v2.4",
    "ssrf": None,  # always available
}


def _check_optional_dep(module_name: str) -> bool:
    """Return True if the optional dependency for a scanner is available."""
    if module_name == "xss_browser":
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False
    if module_name == "zap":
        try:
            from zapv2 import ZAPv2  # noqa: F401
            return True
        except ImportError:
            return False
    if module_name == "ssl":
        try:
            from sslyze import Scanner  # noqa: F401
            return True
        except ImportError:
            # ssl_scanner can still do basic checks without sslyze
            return True
    return True


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="vibecrack",
        description="VibeCrack - Open Source Security Scanner for Web Applications",
        epilog="Want dashboards & history? Try VibeCrack Cloud at https://vibecrack.com",
    )
    parser.add_argument(
        "target",
        help="Target URL to scan (e.g. https://example.com)",
    )
    parser.add_argument(
        "--modules", "-m",
        help="Comma-separated list of scanner modules to run",
    )
    parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Quick scan (crawler + recon + SSL + headers only)",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        metavar="PATH",
        help="Save results as JSON to this path",
    )
    parser.add_argument(
        "--html",
        dest="html_output",
        metavar="PATH",
        help="Generate a self-contained HTML report",
    )
    parser.add_argument(
        "--pdf",
        dest="pdf_output",
        metavar="PATH",
        help="Generate a PDF report (requires reportlab)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed scanner logs",
    )
    return parser.parse_args(argv)


def _write_json(path: str, store, scan_id: str, score_data: dict) -> None:
    """Write scan results as JSON."""
    findings = store.get_vulnerabilities(scan_id)
    scan = store.get_scan_data(scan_id)

    # Serialize datetime objects
    def _serialize(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return str(obj)

    output = {
        "target": scan.get("domain"),
        "scanType": scan.get("scanType"),
        "score": score_data,
        "summary": scan.get("summary", {}),
        "detectedTech": scan.get("detectedTech", []),
        "findings": [
            {
                "severity": f.get("severity"),
                "title": f.get("title"),
                "description": f.get("description"),
                "evidence": f.get("evidence"),
                "remediation": f.get("remediation"),
                "affectedUrl": f.get("affectedUrl"),
                "scanner": f.get("scanner"),
                "owaspCategory": f.get("owaspCategory"),
                "cvssScore": f.get("cvssScore"),
            }
            for f in findings
        ],
        "scannedAt": datetime.now(timezone.utc).isoformat(),
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=_serialize, ensure_ascii=False)


def main(argv=None):
    args = parse_args(argv)

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Initialize CLI output
    from engine.cli_output import CLIOutput
    cli = CLIOutput(no_color=args.no_color, verbose=args.verbose)

    # Validate target
    target = args.target.strip().rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    # Determine modules
    if args.modules:
        modules = [m.strip() for m in args.modules.split(",")]
    elif args.quick:
        modules = list(QUICK_MODULES)
    else:
        modules = list(FULL_MODULES)

    # Filter out modules with missing optional dependencies
    available_modules = []
    for mod in modules:
        if _check_optional_dep(mod):
            available_modules.append(mod)
        else:
            dep = _OPTIONAL_DEP_MODULES.get(mod, mod)
            cli.on_log(
                "warning",
                f"Skipping '{mod}' (requires: pip install {dep})",
                "cli",
            )
    modules = available_modules

    if not modules:
        cli.print_error("No scanner modules available. Check your dependencies.")
        sys.exit(1)

    # Ensure crawler is first if present
    if "crawler" in modules:
        modules.remove("crawler")
        modules.insert(0, "crawler")

    cli.print_banner(target, modules)

    # Create local data store
    from engine.orchestrator.data_store import LocalDataStore, ScanSnapshot

    scan_id = str(uuid.uuid4())
    scan_type = "quick" if args.quick else "full"

    store = LocalDataStore(
        on_log=cli.on_log,
        on_finding=cli.on_finding,
        on_progress=cli.update_progress,
    )
    store.create_scan(scan_id, target, modules, scan_type=scan_type)

    # Create snapshot for JobManager
    snapshot = ScanSnapshot(scan_id, store.get_scan_data(scan_id))

    # Start progress display
    cli.start_progress()

    # Run the scan
    from engine.orchestrator.job_manager import JobManager

    try:
        manager = JobManager(snapshot, data_store=store)
        manager.run()
    except KeyboardInterrupt:
        cli.stop_progress()
        cli.print_error("Scan cancelled by user")
        sys.exit(130)
    except Exception as e:
        cli.stop_progress()
        cli.print_error(f"Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    cli.stop_progress()

    # Display results
    cli.print_summary_counts()
    cli.print_findings()

    score_data = store.get_score(scan_id)
    cli.print_score(score_data or {})

    # Generate output files
    output_files: dict[str, str] = {}

    if args.json_output:
        _write_json(args.json_output, store, scan_id, score_data)
        output_files["JSON"] = os.path.abspath(args.json_output)

    if args.html_output:
        try:
            from engine.reporting.html_report import generate_html_report
            html = generate_html_report(store, scan_id)
            with open(args.html_output, "w", encoding="utf-8") as f:
                f.write(html)
            output_files["HTML"] = os.path.abspath(args.html_output)
        except Exception as e:
            cli.print_error(f"HTML report failed: {e}")

    if args.pdf_output:
        try:
            from engine.reporting.pdf_generator import generate_report
            pdf_bytes = generate_report(scan_id, "full", data_store=store)
            with open(args.pdf_output, "wb") as f:
                f.write(pdf_bytes)
            output_files["PDF"] = os.path.abspath(args.pdf_output)
        except ImportError:
            cli.print_error("PDF requires reportlab: pip install vibecrack[full]")
        except Exception as e:
            cli.print_error(f"PDF report failed: {e}")

    # Auto-save JSON if no output specified
    if not output_files:
        safe_domain = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        auto_json = f"vibecrack_{safe_domain}.json"
        _write_json(auto_json, store, scan_id, score_data)
        output_files["JSON"] = os.path.abspath(auto_json)

    cli.print_output_files(output_files)
    cli.print_cta()


if __name__ == "__main__":
    main()
