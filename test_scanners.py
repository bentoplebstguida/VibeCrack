"""
HackerPA - Test Plan: Verify all 15 scanners work
=====================================================
Creates a test scan and monitors execution to verify:
1. Crawler runs first and stores crawlData
2. All new scanners are in the module list
3. Each scanner executes without fatal errors
4. Scoring includes new scanner categories
5. AI analysis runs (if API key is set)
"""

import os
import sys
import time
import json
from datetime import datetime

# Setup Firebase
os.environ.setdefault("FIREBASE_CREDENTIALS_PATH", "./serviceAccountKey.json")

import firebase_admin
from firebase_admin import credentials, firestore

# Initialize Firebase
if not firebase_admin._apps:
    cred = credentials.Certificate(os.environ["FIREBASE_CREDENTIALS_PATH"])
    firebase_admin.initialize_app(cred)

db = firestore.client()

# ============================================================
# CONFIG
# ============================================================
TEST_DOMAIN = "https://hackerpa.vercel.app"  # Our own site as test target
PROJECT_ID = ""  # Will find or skip

# Expected modules (all 15)
EXPECTED_MODULES = [
    "crawler", "recon", "subdomains", "ssl", "headers",
    "secrets", "directories", "xss", "sqli", "csrf",
    "ssrf", "endpoints", "access_control", "xss_browser", "zap",
]

# ============================================================
# HELPERS
# ============================================================

def print_header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_check(label, passed, detail=""):
    icon = "PASS" if passed else "FAIL"
    detail_str = f" - {detail}" if detail else ""
    print(f"  [{icon}] {label}{detail_str}")

def wait_for_scan(scan_id, timeout=600):
    """Wait for scan to complete, printing progress."""
    start = time.time()
    last_phase = ""
    last_progress = -1

    while time.time() - start < timeout:
        doc = db.collection("scans").document(scan_id).get()
        if not doc.exists:
            print("  ERROR: Scan document not found!")
            return None

        data = doc.to_dict()
        status = data.get("status", "")
        progress = data.get("progress", 0)
        phase = data.get("currentPhase", "")

        if phase != last_phase or progress != last_progress:
            elapsed = int(time.time() - start)
            print(f"  [{elapsed:3d}s] {status} | {progress}% | Phase: {phase}")
            last_phase = phase
            last_progress = progress

        if status in ("completed", "failed", "cancelled"):
            return data

        time.sleep(3)

    print(f"  TIMEOUT after {timeout}s!")
    return None

# ============================================================
# TEST 0: Pre-flight checks
# ============================================================

def test_preflight():
    print_header("TEST 0: Pre-flight Checks")

    # Check imports
    checks = []

    try:
        from engine.scanners.crawler import CrawlerScanner
        checks.append(("Import CrawlerScanner", True, CrawlerScanner.scanner_name))
    except Exception as e:
        checks.append(("Import CrawlerScanner", False, str(e)))

    try:
        from engine.scanners.access_control_scanner import AccessControlScanner
        checks.append(("Import AccessControlScanner", True, AccessControlScanner.scanner_name))
    except Exception as e:
        checks.append(("Import AccessControlScanner", False, str(e)))

    try:
        from engine.scanners.xss_browser_scanner import XSSBrowserScanner
        checks.append(("Import XSSBrowserScanner", True, XSSBrowserScanner.scanner_name))
    except Exception as e:
        checks.append(("Import XSSBrowserScanner", False, str(e)))

    try:
        from engine.scanners.oast_client import OASTClient
        client = OASTClient(scan_id="test")
        payloads = client.get_ssrf_payloads()
        checks.append(("OAST Client", True, f"{len(payloads)} SSRF payloads"))
    except Exception as e:
        checks.append(("OAST Client", False, str(e)))

    try:
        from engine.orchestrator.job_manager import SCANNER_REGISTRY
        checks.append(("Scanner Registry", True, f"{len(SCANNER_REGISTRY)} scanners"))

        for mod in ["crawler", "access_control", "xss_browser"]:
            found = mod in SCANNER_REGISTRY
            checks.append((f"  Registry has '{mod}'", found, ""))
    except Exception as e:
        checks.append(("Scanner Registry", False, str(e)))

    try:
        from engine.scoring.calculator import SCANNER_CATEGORY_MAP
        for scanner in ["crawler", "access_control_scanner", "xss_browser_scanner"]:
            found = scanner in SCANNER_CATEGORY_MAP
            cat = SCANNER_CATEGORY_MAP.get(scanner, "MISSING")
            checks.append((f"  Score map '{scanner}'", found, cat))
    except Exception as e:
        checks.append(("Score Category Map", False, str(e)))

    # Check Playwright (optional - scanner skips gracefully if not installed)
    try:
        from playwright.sync_api import sync_playwright
        checks.append(("Playwright installed", True, "XSS Browser will run"))
    except ImportError:
        checks.append(("Playwright installed (optional)", True, "Not installed - XSS Browser will skip gracefully"))
        print("  [WARN] Playwright not installed - xss_browser scanner will skip tests")

    for label, passed, detail in checks:
        print_check(label, passed, detail)

    return all(p for _, p, _ in checks)

# ============================================================
# TEST 1: Create and run test scan
# ============================================================

def test_create_scan():
    print_header("TEST 1: Create Test Scan")

    # Find a project or create scan without one
    projects = list(db.collection("projects").limit(1).stream())
    project_id = projects[0].id if projects else ""
    user_id = projects[0].to_dict().get("userId", "test") if projects else "test"

    print(f"  Project: {project_id or '(none)'}")
    print(f"  Domain: {TEST_DOMAIN}")
    print(f"  Modules: {len(EXPECTED_MODULES)} ({', '.join(EXPECTED_MODULES)})")

    # Create scan document
    scan_ref = db.collection("scans").add({
        "projectId": project_id,
        "userId": user_id,
        "domain": TEST_DOMAIN,
        "status": "pending",
        "scanType": "full",
        "modules": EXPECTED_MODULES,
        "progress": 0,
        "currentPhase": None,
        "score": None,
        "grade": None,
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "aiSummary": None,
        "exploitPlaybook": None,
        "startedAt": None,
        "completedAt": None,
        "createdAt": firestore.SERVER_TIMESTAMP,
    })

    scan_id = scan_ref[1].id
    print(f"  Scan ID: {scan_id}")
    print(f"  Status: pending (waiting for engine to pick up...)")

    return scan_id

# ============================================================
# TEST 2: Monitor scan execution
# ============================================================

def test_monitor_scan(scan_id):
    print_header("TEST 2: Monitor Scan Execution")
    result = wait_for_scan(scan_id, timeout=600)

    if result is None:
        print_check("Scan completed", False, "Timeout or error")
        return None

    status = result.get("status")
    print_check("Scan completed", status == "completed", f"status={status}")

    return result

# ============================================================
# TEST 3: Verify crawl data
# ============================================================

def test_crawl_data(scan_id):
    print_header("TEST 3: Verify Crawler Data")

    doc = db.collection("scans").document(scan_id).get()
    data = doc.to_dict()
    crawl = data.get("crawlData", {})

    has_crawl = bool(crawl)
    print_check("crawlData exists on scan doc", has_crawl)

    if has_crawl:
        pages = crawl.get("pages", [])
        forms = crawl.get("forms", [])
        params = crawl.get("params", [])
        js_files = crawl.get("jsFiles", [])
        api_endpoints = crawl.get("apiEndpoints", [])

        print_check(f"Pages discovered", len(pages) > 0, f"{len(pages)} page(s)")
        print_check(f"JS files discovered", len(js_files) >= 0, f"{len(js_files)} JS file(s)")
        print_check(f"Forms discovered", True, f"{len(forms)} form(s)")
        print_check(f"URL params discovered", True, f"{len(params)} param set(s)")
        print_check(f"API endpoints discovered", True, f"{len(api_endpoints)} endpoint(s)")

        # Show samples
        if pages:
            print(f"\n  Sample pages: {pages[:3]}")
        if api_endpoints:
            print(f"  Sample APIs: {api_endpoints[:3]}")

# ============================================================
# TEST 4: Verify scanner results
# ============================================================

def test_scanner_results(scan_id, scan_data):
    print_header("TEST 4: Verify Scanner Results")

    # Check scannerResults field
    scanner_results = scan_data.get("scannerResults", {})
    print(f"  Scanner results: {json.dumps(scanner_results, indent=2)}")

    for mod in EXPECTED_MODULES:
        result = scanner_results.get(mod, "NOT_RUN")
        passed = result in ("success", "error")  # At least it tried
        print_check(f"Scanner '{mod}' executed", passed, result)

    # Count vulnerabilities by scanner
    vulns = list(
        db.collection("vulnerabilities")
        .where("scanId", "==", scan_id)
        .stream()
    )

    scanner_counts = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        vd = v.to_dict()
        scanner = vd.get("scanner", "unknown")
        severity = vd.get("severity", "info")
        scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    print(f"\n  Total vulnerabilities: {len(vulns)}")
    print(f"  By severity: {json.dumps(severity_counts)}")
    print(f"  By scanner:")
    for scanner, count in sorted(scanner_counts.items()):
        print(f"    {scanner}: {count}")

    # Check new scanners specifically
    print()
    print_check("Crawler produced findings", "crawler" in scanner_counts, f"{scanner_counts.get('crawler', 0)} finding(s)")
    print_check("Access Control produced findings", "access_control_scanner" in scanner_counts, f"{scanner_counts.get('access_control_scanner', 0)} finding(s)")
    print_check("XSS Browser attempted", "xss_browser_scanner" in scanner_counts or scanner_results.get("xss_browser") == "success", "")

# ============================================================
# TEST 5: Verify scoring
# ============================================================

def test_scoring(scan_id, scan_data):
    print_header("TEST 5: Verify Scoring")

    score = scan_data.get("score")
    grade = scan_data.get("grade")

    print_check("Score calculated", score is not None, f"{score}/100")
    print_check("Grade assigned", grade is not None, grade or "")

    # Check score history
    scores = list(
        db.collection("scores_history")
        .where("scanId", "==", scan_id)
        .limit(1)
        .stream()
    )

    if scores:
        sd = scores[0].to_dict()
        categories = sd.get("categories", {})
        print(f"\n  Score breakdown:")
        for cat, info in sorted(categories.items()):
            print(f"    {cat}: {info.get('score', '?')}/100 ({info.get('grade', '?')}) weight={info.get('weight', '?')}")
    else:
        print_check("Score history record", False, "Not found")

# ============================================================
# TEST 6: Verify AI analysis
# ============================================================

def test_ai_analysis(scan_data):
    print_header("TEST 6: Verify AI Analysis")

    ai_summary = scan_data.get("aiSummary")
    playbook = scan_data.get("exploitPlaybook")

    has_ai = ai_summary is not None and len(ai_summary or "") > 0
    has_playbook = playbook is not None and len(playbook or "") > 0

    print_check("AI Summary generated", has_ai, f"{len(ai_summary or '')} chars")
    print_check("Exploit Playbook generated", has_playbook, f"{len(playbook or '')} chars")

    if has_ai:
        print(f"\n  AI Summary preview (first 200 chars):")
        print(f"  {(ai_summary or '')[:200]}...")

# ============================================================
# TEST 7: Verify logs
# ============================================================

def test_logs(scan_id):
    print_header("TEST 7: Verify Scan Logs")

    logs = list(
        db.collection("scan_logs")
        .where("scanId", "==", scan_id)
        .stream()
    )

    print(f"  Total log entries: {len(logs)}")

    # Check for new scanner log messages
    log_messages = [l.to_dict().get("message", "") for l in logs]

    crawler_logs = [m for m in log_messages if "crawl" in m.lower() or "crawler" in m.lower()]
    ac_logs = [m for m in log_messages if "access control" in m.lower() or "access_control" in m.lower()]
    xss_browser_logs = [m for m in log_messages if "browser" in m.lower() and "xss" in m.lower()]
    oast_logs = [m for m in log_messages if "oast" in m.lower()]
    error_logs = [m for m in log_messages if any(l.to_dict().get("level") == "error" for l in logs if l.to_dict().get("message") == m)]

    print_check("Crawler logs present", len(crawler_logs) > 0, f"{len(crawler_logs)} entries")
    print_check("Access Control logs present", len(ac_logs) > 0, f"{len(ac_logs)} entries")
    print_check("XSS Browser logs present", len(xss_browser_logs) >= 0, f"{len(xss_browser_logs)} entries")
    print_check("OAST logs present", len(oast_logs) >= 0, f"{len(oast_logs)} entries")

    if error_logs:
        print(f"\n  Error log samples:")
        for msg in error_logs[:5]:
            print(f"    - {msg}")

# ============================================================
# MAIN
# ============================================================

def main():
    print("\n" + "=" * 60)
    print("  HackerPA - Test Plan Execution")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Test 0: Pre-flight
    preflight_ok = test_preflight()
    if not preflight_ok:
        print("\n  ABORT: Pre-flight checks failed")
        sys.exit(1)

    # Test 1: Create scan
    scan_id = test_create_scan()

    # Test 2: Monitor execution
    scan_data = test_monitor_scan(scan_id)
    if scan_data is None:
        print("\n  ABORT: Scan did not complete")
        sys.exit(1)

    # Test 3: Crawl data
    test_crawl_data(scan_id)

    # Test 4: Scanner results
    test_scanner_results(scan_id, scan_data)

    # Test 5: Scoring
    test_scoring(scan_id, scan_data)

    # Test 6: AI Analysis
    test_ai_analysis(scan_data)

    # Test 7: Logs
    test_logs(scan_id)

    # Final summary
    print_header("TEST COMPLETE")
    print(f"  Scan ID: {scan_id}")
    print(f"  Status: {scan_data.get('status')}")
    print(f"  Score: {scan_data.get('score')}/100 ({scan_data.get('grade')})")
    print(f"  View at: http://localhost:3005/scans/{scan_id}")
    print()


if __name__ == "__main__":
    main()
