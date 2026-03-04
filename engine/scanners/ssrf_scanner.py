"""
VibeCrack Engine - SSRF & RCE Validation Scanner

Tests for Server-Side Request Forgery (SSRF) by attempting to make the
target server fetch internal resources or callback URLs. Also checks for
Remote Code Execution (RCE) indicators in error responses.

Integrates with OASTClient for out-of-band blind SSRF detection when
an external callback URL is configured via ``OAST_CALLBACK_URL``.

Non-destructive: uses only read operations and timing analysis.
"""

import logging
import re
import time
from urllib.parse import urljoin, urlencode, urlparse, parse_qs, urlunparse

from bs4 import BeautifulSoup

from engine.scanners.base_scanner import BaseScanner
from engine.scanners.oast_client import OASTClient

logger = logging.getLogger(__name__)

# Internal IPs/URLs to test SSRF against
SSRF_PAYLOADS = [
    # Localhost variants
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    # Bypass attempts
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:3000",
    # Cloud metadata endpoints (read-only)
    "http://169.254.169.254/latest/meta-data/",          # AWS
    "http://metadata.google.internal/computeMetadata/v1/", # GCP
    "http://169.254.169.254/metadata/instance",            # Azure
    # URL schema tricks
    "http://2130706433",               # 127.0.0.1 as decimal
    "http://0x7f000001",               # 127.0.0.1 as hex
    "http://017700000001",             # 127.0.0.1 as octal
    "http://127.1",                    # Short form
    # File protocol (if supported)
    "file:///etc/passwd",
    "file:///c:/windows/system.ini",
]

# Parameters commonly vulnerable to SSRF
SSRF_PARAM_NAMES = [
    "url", "uri", "link", "src", "source", "href", "path", "file",
    "page", "document", "folder", "root", "dir", "site", "host",
    "redirect", "redirect_url", "return", "return_url", "callback",
    "next", "target", "dest", "destination", "domain", "feed",
    "proxy", "api", "endpoint", "fetch", "load", "read", "download",
    "image", "img", "icon", "logo", "avatar", "photo", "picture",
    "pdf", "template", "preview", "view", "ref", "reference",
]

# RCE indicators in responses
RCE_INDICATORS = [
    # Linux passwd file
    r"root:x?:0:0:",
    # Windows system.ini
    r"\[drivers\]",
    r"\[extensions\]",
    # Command output patterns
    r"uid=\d+\([\w-]+\)\s+gid=\d+",  # id command output
    r"(?:Linux|Darwin|Windows)\s+\S+\s+\d+",  # uname output
    # Cloud metadata
    r"ami-[a-f0-9]+",                # AWS AMI ID
    r"instance-id",                   # Cloud instance
    r"iam/security-credentials",      # AWS IAM
    # Error messages indicating SSRF potential
    r"Connection refused.*127\.0\.0\.1",
    r"Connection refused.*localhost",
    r"couldn't connect to host",
    r"getaddrinfo.*failed",
]

# Patterns indicating server tried to fetch the URL (even if blocked)
SSRF_EVIDENCE_PATTERNS = [
    r"Connection refused",
    r"Connection timed out",
    r"No route to host",
    r"Name or service not known",
    r"getaddrinfo",
    r"curl_exec",
    r"file_get_contents",
    r"fopen\(",
    r"java\.net\.ConnectException",
    r"java\.net\.UnknownHostException",
    r"urllib",
    r"requests\.exceptions",
    r"ECONNREFUSED",
    r"ETIMEDOUT",
]


class SSRFScanner(BaseScanner):
    scanner_name = "ssrf_scanner"

    def __init__(self, scan_id: str, project_id: str, domain: str, **kwargs) -> None:
        super().__init__(scan_id, project_id, domain, **kwargs)
        # Initialise OAST client for blind SSRF detection
        try:
            self._oast = OASTClient(scan_id=scan_id)
        except Exception as exc:
            logger.warning("Could not initialise OASTClient: %s", exc)
            self._oast = None

    def run(self) -> None:
        self.log("info", f"Testing SSRF/RCE for {self.base_url}")

        # 1. Capture a baseline response time for timing analysis
        baseline_start = time.time()
        response = self.make_request(self.base_url)
        self._baseline_time = time.time() - baseline_start

        if response is None:
            self.log("error", f"Could not reach {self.base_url}")
            return

        # 2. Find forms and links with URL-like parameters
        injectable_points = self._find_injectable_points(response.text)
        self.log("info", f"Found {len(injectable_points)} potential SSRF injection points")

        # 3. Test each point with standard payloads
        for point in injectable_points:
            self._test_ssrf(point)

        # 4. Test each point with OAST-enhanced payloads (bypasses + callbacks)
        if self._oast is not None:
            self._test_oast_ssrf(injectable_points)

        # 5. Test common API patterns for SSRF
        self._test_common_ssrf_endpoints()

        # 6. Check for RCE indicators in error pages
        self._check_rce_indicators()

        # 7. Check OAST callbacks for blind hits
        if self._oast is not None:
            self._check_oast_callbacks()

        self.log("info", "SSRF/RCE scan complete")

    def _find_injectable_points(self, html: str) -> list[dict]:
        """Find URL parameters that might be vulnerable to SSRF."""
        points = []
        try:
            soup = BeautifulSoup(html, "lxml")

            # Check all links for URL-like parameters
            for tag in soup.find_all(["a", "form", "img", "iframe", "script"]):
                url = tag.get("href") or tag.get("action") or tag.get("src") or ""
                if not url or url.startswith("#") or url.startswith("javascript:"):
                    continue

                full_url = urljoin(self.base_url, url)
                parsed = urlparse(full_url)

                # Only test same-origin URLs
                base_parsed = urlparse(self.base_url)
                if parsed.hostname != base_parsed.hostname:
                    continue

                params = parse_qs(parsed.query)
                for param_name in params:
                    if param_name.lower() in SSRF_PARAM_NAMES:
                        points.append({
                            "url": full_url,
                            "param": param_name,
                            "method": "GET",
                        })

            # Check forms with URL-like input fields
            for form in soup.find_all("form"):
                action = urljoin(self.base_url, form.get("action", ""))
                method = (form.get("method", "GET")).upper()

                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name", "")
                    if name.lower() in SSRF_PARAM_NAMES:
                        points.append({
                            "url": action,
                            "param": name,
                            "method": method,
                        })

        except Exception as e:
            self.log("warning", f"Error parsing HTML for SSRF points: {e}")

        return points

    def _test_ssrf(self, point: dict) -> None:
        """Test a single injection point for SSRF."""
        url = point["url"]
        param = point["param"]
        method = point["method"]

        # Test a subset of payloads to avoid excessive requests
        test_payloads = SSRF_PAYLOADS[:8]

        for payload in test_payloads:
            if method == "GET":
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                response = self.make_request(test_url)
            else:
                data = {param: payload}
                response = self.make_request(url, method="POST", data=data)

            if response is None:
                continue

            body = response.text

            # Check for RCE indicators (actual file contents leaked)
            for pattern in RCE_INDICATORS:
                if re.search(pattern, body, re.IGNORECASE):
                    self.add_finding(
                        severity="critical",
                        title=f"Confirmed SSRF with possible RCE via parameter '{param}'",
                        description=(
                            f"The server processed an internal/malicious URL provided in the parameter '{param}'. "
                            f"The response content indicates the server executed the request, "
                            f"potentially exposing internal files, cloud metadata, or allowing command execution."
                        ),
                        evidence={
                            "url": url,
                            "payload": f"{param}={payload}",
                            "response_snippet": body[:300],
                        },
                        remediation=(
                            "1. NEVER use user input directly in server-side requests.\n"
                            "2. Implement an allowlist of permitted domains/IPs.\n"
                            "3. Block requests to private IPs (127.0.0.1, 10.x, 172.16.x, 192.168.x).\n"
                            "4. Block requests to cloud metadata (169.254.169.254).\n"
                            "5. Use a URL validation library that rejects dangerous schemes (file://, gopher://)."
                        ),
                        owasp_category="A10:2021 - Server-Side Request Forgery",
                        cvss_score=9.8,
                        affected_url=url,
                    )
                    return  # Critical found, no need to test more

            # Check for evidence that server TRIED to fetch (even if blocked)
            for pattern in SSRF_EVIDENCE_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    self.add_finding(
                        severity="high",
                        title=f"Possible SSRF via parameter '{param}'",
                        description=(
                            f"The server appears to have attempted a request to the URL provided in the parameter '{param}'. "
                            f"The error message indicates the server processed the URL internally. "
                            f"With more elaborate payloads, this could lead to access to internal resources."
                        ),
                        evidence={
                            "url": url,
                            "payload": f"{param}={payload}",
                            "response_snippet": body[:300],
                        },
                        remediation=(
                            "1. Validate and sanitize all user-provided URLs.\n"
                            "2. Use allowlists of permitted domains.\n"
                            "3. Do not expose internal error messages to the user."
                        ),
                        owasp_category="A10:2021 - Server-Side Request Forgery",
                        cvss_score=7.5,
                        affected_url=url,
                    )
                    return

    def _test_common_ssrf_endpoints(self) -> None:
        """Test common API endpoints that often accept URL parameters."""
        common_paths = [
            "/api/proxy?url=",
            "/api/fetch?url=",
            "/api/preview?url=",
            "/api/screenshot?url=",
            "/api/pdf?url=",
            "/api/image?url=",
            "/api/import?url=",
            "/api/webhook?url=",
            "/proxy?url=",
            "/fetch?url=",
            "/redirect?url=",
            "/load?url=",
        ]

        test_payload = "http://127.0.0.1:80"

        for path in common_paths:
            url = urljoin(self.base_url.rstrip("/"), path + test_payload)
            response = self.make_request(url, timeout=10)

            if response is None:
                continue

            # Skip 404s
            if response.status_code == 404:
                continue

            body = response.text
            # Check if server processed the internal URL
            for pattern in RCE_INDICATORS + SSRF_EVIDENCE_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    self.add_finding(
                        severity="high",
                        title=f"Proxy/fetch endpoint vulnerable to SSRF: {path.split('?')[0]}",
                        description=(
                            f"The endpoint '{path.split('?')[0]}' accepts URLs and attempts to fetch them server-side. "
                            f"This can be exploited to access internal network resources."
                        ),
                        evidence={
                            "url": url,
                            "payload": test_payload,
                            "response_snippet": body[:300],
                        },
                        remediation=(
                            "1. Remove unnecessary proxy endpoints.\n"
                            "2. If needed, implement a strict domain allowlist.\n"
                            "3. Block private IPs and cloud metadata IPs."
                        ),
                        owasp_category="A10:2021 - Server-Side Request Forgery",
                        cvss_score=8.0,
                        affected_url=url,
                    )
                    break

    def _check_rce_indicators(self) -> None:
        """Check error pages for indicators of command execution or path traversal."""
        rce_paths = [
            "/..%2f..%2f..%2f..%2fetc/passwd",
            "/..%252f..%252f..%252fetc/passwd",
            "/?cmd=id",
            "/?exec=whoami",
            "/?command=uname+-a",
            "/cgi-bin/test.cgi",
            "/debug/vars",
            "/actuator/env",
        ]

        for path in rce_paths:
            url = urljoin(self.base_url.rstrip("/"), path)
            response = self.make_request(url, timeout=10)

            if response is None or response.status_code == 404:
                continue

            body = response.text

            for pattern in RCE_INDICATORS:
                if re.search(pattern, body, re.IGNORECASE):
                    self.add_finding(
                        severity="critical",
                        title="Possible Remote Code Execution (RCE) detected",
                        description=(
                            f"The endpoint '{path}' returned content indicating command execution "
                            f"or system file access. This is a critical vulnerability that "
                            f"allows full control of the server."
                        ),
                        evidence={
                            "url": url,
                            "payload": path,
                            "response_snippet": body[:300],
                        },
                        remediation=(
                            "1. URGENT: Disable any endpoint that executes system commands.\n"
                            "2. Never pass user input to functions like exec(), system(), eval().\n"
                            "3. Remove unnecessary CGI scripts.\n"
                            "4. Disable debug endpoints in production.\n"
                            "5. Update the framework to the latest version."
                        ),
                        owasp_category="A03:2021 - Injection",
                        cvss_score=10.0,
                        affected_url=url,
                    )
                    return

    # ------------------------------------------------------------------
    # OAST-enhanced SSRF testing
    # ------------------------------------------------------------------

    def _test_oast_ssrf(self, injectable_points: list[dict]) -> None:
        """Test injection points with OAST-enhanced payloads: advanced
        bypass techniques, callback URLs, DNS canaries, and timing analysis."""
        if self._oast is None:
            return

        oast_payloads = self._oast.get_ssrf_payloads()
        self.log("info", f"Testing {len(oast_payloads)} OAST-enhanced SSRF payloads across {len(injectable_points)} injection point(s)")

        for point in injectable_points:
            url = point["url"]
            param = point["param"]
            method = point["method"]

            # Test a limited set of the most impactful OAST payloads
            # to keep request count reasonable
            for payload_entry in oast_payloads[:15]:
                payload_url = payload_entry["url"]
                payload_tag = payload_entry["tag"]
                payload_desc = payload_entry["description"]

                # Send the payload
                test_start = time.time()
                if method == "GET":
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param] = [payload_url]
                    new_query = urlencode(params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    response = self.make_request(test_url, timeout=10)
                else:
                    data = {param: payload_url}
                    response = self.make_request(url, method="POST", data=data, timeout=10)
                test_time = time.time() - test_start

                if response is None:
                    continue

                body = response.text

                # 1. Analyse response for cloud metadata / file contents
                analysis = self._oast.analyse_response(body, payload_tag=payload_tag)
                if analysis["matched"]:
                    severity = "critical" if analysis["category"] in (
                        "aws_meta", "gcp_meta", "azure_meta", "file_read"
                    ) else "high"

                    self.add_finding(
                        severity=severity,
                        title=f"Confirmed SSRF via bypass ({payload_desc}) on parameter '{param}'",
                        description=(
                            f"The server processed a URL using the bypass technique '{payload_desc}' "
                            f"provided in the parameter '{param}'. The response contains evidence of access to "
                            f"internal resources (category: {analysis['category']}). "
                            f"Patterns found: {', '.join(analysis['patterns'][:3])}."
                        ),
                        evidence={
                            "url": url,
                            "payload": f"{param}={payload_url}",
                            "bypass_technique": payload_desc,
                            "evidence_category": analysis["category"],
                            "matched_patterns": analysis["patterns"][:5],
                            "response_snippet": analysis["snippet"][:300],
                        },
                        remediation=(
                            "1. NEVER use user input directly in server-side requests.\n"
                            "2. Implement strict URL validation: resolve the hostname to IP "
                            "and verify it is not a private IP BEFORE making the request.\n"
                            "3. Block dangerous schemes: file://, gopher://, dict://, ftp://.\n"
                            "4. Use domain/IP allowlists instead of blocklists.\n"
                            "5. Disable redirects in server-side requests.\n"
                            "6. Block cloud metadata (169.254.169.254) at the firewall/network level.\n"
                            "7. Migrate to IMDSv2 (AWS) which requires a session token."
                        ),
                        owasp_category="A10:2021 - Server-Side Request Forgery",
                        cvss_score=9.8 if severity == "critical" else 8.0,
                        affected_url=url,
                    )
                    return  # Critical found on this point, move on

                # 2. Check standard RCE/SSRF evidence patterns
                for pattern in RCE_INDICATORS + SSRF_EVIDENCE_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        self.add_finding(
                            severity="high",
                            title=f"SSRF detected via bypass ({payload_desc}) on parameter '{param}'",
                            description=(
                                f"The server attempted to process the URL using the technique '{payload_desc}' "
                                f"on parameter '{param}'. The response contains indicators that the server "
                                f"made an internal request."
                            ),
                            evidence={
                                "url": url,
                                "payload": f"{param}={payload_url}",
                                "bypass_technique": payload_desc,
                                "response_snippet": body[:300],
                            },
                            remediation=(
                                "1. Validate and sanitize all user-provided URLs.\n"
                                "2. Resolve hostnames to IP and block private ranges.\n"
                                "3. Block dangerous schemes (file://, gopher://, dict://).\n"
                                "4. Do not expose internal error messages to the user."
                            ),
                            owasp_category="A10:2021 - Server-Side Request Forgery",
                            cvss_score=7.5,
                            affected_url=url,
                        )
                        break

                # 3. Timing-based blind SSRF detection
                timing = self._oast.analyse_timing(self._baseline_time, test_time)
                if timing["suspicious"]:
                    self.add_finding(
                        severity="medium",
                        title=f"Possible blind SSRF via timing on parameter '{param}'",
                        description=(
                            f"The response time for parameter '{param}' with payload "
                            f"'{payload_desc}' was {timing['factor']}x slower than the baseline "
                            f"({timing['baseline_ms']}ms vs {timing['test_ms']}ms). "
                            f"This may indicate the server is trying to fetch the URL internally."
                        ),
                        evidence={
                            "url": url,
                            "payload": f"{param}={payload_url}",
                            "bypass_technique": payload_desc,
                            "baseline_ms": timing["baseline_ms"],
                            "test_ms": timing["test_ms"],
                            "slowdown_factor": timing["factor"],
                        },
                        remediation=(
                            "1. Investigate whether the server makes external requests based on user input.\n"
                            "2. Implement short timeouts for server-side requests (max 3 seconds).\n"
                            "3. Use domain allowlists and block private IPs.\n"
                            "4. Consider using an egress proxy with firewall rules."
                        ),
                        owasp_category="A10:2021 - Server-Side Request Forgery",
                        cvss_score=5.0,
                        affected_url=url,
                    )

    def _check_oast_callbacks(self) -> None:
        """Poll the OAST callback service for any hits received during
        the scan.  Each hit confirms a blind SSRF vulnerability."""
        if self._oast is None:
            return

        self.log("info", "Checking OAST callbacks for blind SSRF hits")

        # Brief delay to allow outbound requests to arrive
        time.sleep(2)

        try:
            hits = self._oast.check_callbacks()
        except Exception as exc:
            self.log("warning", f"Error checking OAST callbacks: {exc}")
            return

        for hit in hits:
            tag = hit.get("tag", "unknown")
            token = hit.get("token", "")
            source_ip = hit.get("source_ip", "unknown")

            self.add_finding(
                severity="critical",
                title=f"Confirmed blind SSRF via OAST callback (tag: {tag})",
                description=(
                    f"The target server made an outbound request to the OAST endpoint, "
                    f"confirming a blind SSRF vulnerability. The callback was received "
                    f"with token '{token}' (tag: {tag}) originating from IP {source_ip}. "
                    f"This means an attacker can make the server fetch arbitrary URLs, "
                    f"potentially accessing internal network resources."
                ),
                evidence={
                    "oast_tag": tag,
                    "oast_token": token,
                    "source_ip": source_ip,
                    "timestamp": hit.get("timestamp", ""),
                    "confirmation": "Out-of-band callback received at OAST endpoint",
                },
                remediation=(
                    "1. CRITICAL: The server is making external requests based on user input.\n"
                    "2. Implement strict URL validation on the server-side.\n"
                    "3. Block all unnecessary outbound requests at the firewall.\n"
                    "4. Use domain allowlists and block private IP ranges.\n"
                    "5. Disable dangerous schemes (file://, gopher://, dict://).\n"
                    "6. Migrate to IMDSv2 (AWS) and configure firewall to block 169.254.169.254."
                ),
                owasp_category="A10:2021 - Server-Side Request Forgery",
                cvss_score=9.8,
                affected_url=self.base_url,
            )
