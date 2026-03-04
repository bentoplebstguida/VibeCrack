"""
VibeCrack Engine - Endpoint Discovery & Access Control Scanner

Discovers API endpoints by:
  - Parsing HTML and JavaScript for API URLs (fetch/axios calls, hrefs)
  - Testing common API paths (/api/v1/users, /api/health, /graphql, etc.)

For each discovered endpoint, tests for:
  - Missing authentication (accessing without credentials)
  - Broken access control (endpoints returning data without auth)
  - Information disclosure (stack traces, debug info in error responses)
"""

import re
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from engine.scanners.base_scanner import BaseScanner


# Common API paths to probe for endpoint discovery
COMMON_API_PATHS: list[str] = [
    # REST API versioned
    "/api",
    "/api/",
    "/api/v1",
    "/api/v1/",
    "/api/v1/users",
    "/api/v1/admin",
    "/api/v1/config",
    "/api/v1/settings",
    "/api/v1/profile",
    "/api/v1/accounts",
    "/api/v1/status",
    "/api/v2",
    "/api/v2/users",
    # Common REST endpoints
    "/api/users",
    "/api/admin",
    "/api/config",
    "/api/settings",
    "/api/health",
    "/api/healthcheck",
    "/api/status",
    "/api/info",
    "/api/version",
    "/api/debug",
    "/api/me",
    "/api/profile",
    "/api/accounts",
    "/api/auth",
    "/api/login",
    "/api/register",
    "/api/token",
    "/api/keys",
    "/api/search",
    "/api/export",
    "/api/upload",
    "/api/files",
    "/api/logs",
    "/api/metrics",
    "/api/env",
    # GraphQL
    "/graphql",
    "/graphql/console",
    "/graphiql",
    "/altair",
    "/playground",
    # Common frameworks
    "/rest",
    "/rest/api",
    "/v1",
    "/v2",
    "/_api",
    "/internal/api",
    "/private/api",
    # Actuator / Spring Boot
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/info",
    # WordPress REST
    "/wp-json",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/posts",
    # Common admin APIs
    "/admin/api",
    "/dashboard/api",
    "/management",
    "/internal",
]

# Patterns in error responses that indicate information disclosure
INFO_DISCLOSURE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE), "Python stack trace"),
    (re.compile(r"at\s+[\w.$]+\([\w.]+\.java:\d+\)", re.IGNORECASE), "Java stack trace"),
    (re.compile(r"at\s+[\w.\\/<>]+\s+in\s+[^\s]+:\s*line\s+\d+", re.IGNORECASE), ".NET stack trace"),
    (re.compile(r"Fatal error:.*on line \d+", re.IGNORECASE), "PHP fatal error"),
    (re.compile(r"Stack Trace:", re.IGNORECASE), "Application stack trace"),
    (re.compile(r"Exception in thread", re.IGNORECASE), "Java exception"),
    (re.compile(r"node_modules/", re.IGNORECASE), "Node.js internal path"),
    (re.compile(r'"stack"\s*:\s*".*\\n\s+at\s+', re.IGNORECASE), "JSON stack trace"),
    (re.compile(r"DEBUG\s*=\s*True", re.IGNORECASE), "Debug mode enabled"),
    (re.compile(r"DJANGO_SETTINGS_MODULE", re.IGNORECASE), "Django settings exposed"),
    (re.compile(r'"password"\s*:', re.IGNORECASE), "Password field in response"),
    (re.compile(r'"secret"\s*:', re.IGNORECASE), "Secret field in response"),
    (re.compile(r'"token"\s*:\s*"[A-Za-z0-9_-]{20,}"', re.IGNORECASE), "Token in response"),
    (re.compile(r'"private_key"\s*:', re.IGNORECASE), "Private key in response"),
    (re.compile(r'"database_url"\s*:', re.IGNORECASE), "Database URL in response"),
    (re.compile(r'(?:mysql|postgres|mongodb|redis)://[^\s"\']+', re.IGNORECASE), "Database connection string"),
    (re.compile(r"server_version|server_software", re.IGNORECASE), "Server version disclosure"),
]

# Patterns to extract API URLs from HTML/JS source code
API_URL_PATTERNS: list[re.Pattern] = [
    # fetch("...") / fetch('...')
    re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    # axios.get("..."), axios.post("..."), etc.
    re.compile(r'axios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    # $.ajax({ url: "..." })
    re.compile(r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', re.IGNORECASE),
    # $.get("..."), $.post("...")
    re.compile(r'\$\.(?:get|post)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    # XMLHttpRequest .open("METHOD", "URL")
    re.compile(r'\.open\s*\(\s*["\'](?:GET|POST|PUT|PATCH|DELETE)["\']\s*,\s*["\']([^"\']+)["\']', re.IGNORECASE),
    # Generic /api/ path references in strings
    re.compile(r'["\'](/api/[^"\'?\s]+)["\']', re.IGNORECASE),
    # href="/api/..." or action="/api/..."
    re.compile(r'(?:href|action|src)\s*=\s*["\'](/api/[^"\']+)["\']', re.IGNORECASE),
    # baseURL / apiUrl / API_BASE assignments
    re.compile(r'(?:base_?url|api_?url|api_?base|endpoint)\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
]


class EndpointScanner(BaseScanner):
    """API endpoint discovery and access control scanner.

    Discovers endpoints through source code analysis and common path
    probing, then tests each endpoint for missing authentication,
    broken access control, and information disclosure.
    """

    scanner_name = "endpoint_scanner"

    def run(self) -> None:
        self.log("info", f"Starting endpoint discovery and access control scan for {self.base_url}")

        discovered: dict[str, str] = {}  # url -> discovery_method

        # ------------------------------------------------------------------
        # 1. Fetch the main page and parse for API endpoints
        # ------------------------------------------------------------------
        response = self.make_request(self.base_url)
        if response is None:
            self.log("error", f"Could not reach {self.base_url} - aborting endpoint scan")
            return

        parsed_endpoints = self._parse_endpoints_from_source(response.text, self.base_url)
        for url in parsed_endpoints:
            discovered[url] = "parsed_from_source"

        self.log("info", f"Parsed {len(parsed_endpoints)} endpoint(s) from page source")

        # ------------------------------------------------------------------
        # 2. Parse linked JavaScript files for API endpoints
        # ------------------------------------------------------------------
        js_urls = self._extract_js_urls(response.text, self.base_url)
        self.log("info", f"Found {len(js_urls)} linked JavaScript file(s) to analyse")

        for js_url in js_urls[:20]:  # Limit to avoid excessive requests
            js_resp = self.make_request(js_url)
            if js_resp is None:
                continue
            js_endpoints = self._parse_endpoints_from_source(js_resp.text, self.base_url)
            for url in js_endpoints:
                if url not in discovered:
                    discovered[url] = "parsed_from_js"

        self.log("info", f"Total parsed endpoints (HTML + JS): {len(discovered)}")

        # ------------------------------------------------------------------
        # 3. Probe common API paths
        # ------------------------------------------------------------------
        probed = self._probe_common_paths()
        for url in probed:
            if url not in discovered:
                discovered[url] = "common_path_probe"

        self.log("info", f"Probed common paths: {len(probed)} responded. Total endpoints: {len(discovered)}")

        # ------------------------------------------------------------------
        # 4. Test each discovered endpoint
        # ------------------------------------------------------------------
        for endpoint_url, method in discovered.items():
            self._test_endpoint(endpoint_url, method)

        self.log("info", f"Endpoint scan complete. {len(discovered)} endpoints analysed.")

    # ------------------------------------------------------------------
    # Source code parsing
    # ------------------------------------------------------------------

    def _parse_endpoints_from_source(self, source: str, base_url: str) -> list[str]:
        """Extract API URLs from HTML or JavaScript source code."""
        found: set[str] = set()

        for pattern in API_URL_PATTERNS:
            for match in pattern.finditer(source):
                raw_url = match.group(1)
                resolved = self._resolve_url(raw_url, base_url)
                if resolved and self._is_same_origin(resolved, base_url):
                    found.add(resolved)

        return list(found)

    def _extract_js_urls(self, html: str, base_url: str) -> list[str]:
        """Find <script src="..."> URLs in the HTML."""
        pattern = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
        urls: list[str] = []
        seen: set[str] = set()

        for match in pattern.finditer(html):
            raw = match.group(1)
            resolved = urljoin(base_url, raw)
            if resolved not in seen and self._is_same_origin(resolved, base_url):
                seen.add(resolved)
                urls.append(resolved)

        return urls

    # ------------------------------------------------------------------
    # Common path probing
    # ------------------------------------------------------------------

    def _probe_common_paths(self) -> list[str]:
        """Test common API paths and return those that respond (non-404)."""
        found: list[str] = []

        for path in COMMON_API_PATHS:
            url = self.base_url.rstrip("/") + path
            resp = self.make_request(url, allow_redirects=False)
            if resp is None:
                continue

            # Consider the endpoint "alive" if it does not return 404
            if resp.status_code not in (404, 405, 502, 503):
                found.append(url)

        return found

    # ------------------------------------------------------------------
    # Endpoint testing
    # ------------------------------------------------------------------

    def _test_endpoint(self, url: str, discovery_method: str) -> None:
        """Test a single endpoint for missing auth and info disclosure."""
        resp = self.make_request(url)
        if resp is None:
            return

        # ----- Check for unauthenticated access -------------------------
        self._check_unauthenticated_access(url, resp, discovery_method)

        # ----- Check for information disclosure --------------------------
        self._check_info_disclosure(url, resp)

    def _check_unauthenticated_access(
        self,
        url: str,
        resp: requests.Response,
        discovery_method: str,
    ) -> None:
        """Flag endpoints that return meaningful data without authentication."""
        if resp.status_code in (401, 403, 407):
            # Endpoint correctly requires authentication -- no issue
            self.log("info", f"Endpoint {url} correctly requires auth (HTTP {resp.status_code})")
            return

        if resp.status_code == 200:
            body = resp.text.strip()
            content_type = resp.headers.get("Content-Type", "")

            # Heuristic: if the response is JSON/XML with non-trivial body,
            # it likely contains real data.
            is_data_response = (
                ("application/json" in content_type or "application/xml" in content_type)
                and len(body) > 20
            )

            # Also flag HTML pages that look like admin panels
            is_admin_panel = (
                "text/html" in content_type
                and any(kw in url.lower() for kw in ("admin", "dashboard", "management", "internal"))
                and len(body) > 200
            )

            if is_data_response or is_admin_panel:
                snippet = body[:300]
                severity = "high" if is_admin_panel else "medium"
                title_prefix = "Admin panel" if is_admin_panel else "API endpoint"

                self.add_finding(
                    severity=severity,
                    title=f"{title_prefix} accessible without authentication: {self._short_path(url)}",
                    description=(
                        f"The endpoint {url} returns data (HTTP {resp.status_code}, "
                        f"{content_type}) without requiring authentication. "
                        f"Discovery method: {discovery_method}. An attacker can "
                        f"access this endpoint directly to retrieve potentially "
                        f"sensitive data or perform unauthorized actions."
                    ),
                    evidence={
                        "url": url,
                        "payload": "No authentication token/cookie sent",
                        "response_snippet": snippet,
                    },
                    remediation=(
                        "1. Require authentication (e.g. JWT, session cookie, API key) "
                        "for all sensitive endpoints.\n"
                        "2. Implement proper authorization checks -- verify the "
                        "authenticated user is allowed to access the resource.\n"
                        "3. Return 401 Unauthorized for unauthenticated requests.\n"
                        "4. Return 403 Forbidden for authenticated but unauthorized requests.\n"
                        "5. Do not rely on obscurity (hidden URLs) as a security measure."
                    ),
                    owasp_category="A01:2021 - Broken Access Control",
                    cvss_score=7.5 if is_admin_panel else 5.3,
                    affected_url=url,
                )

    def _check_info_disclosure(self, url: str, resp: requests.Response) -> None:
        """Check the response for stack traces, debug info, and sensitive data."""
        body = resp.text

        for pattern, description in INFO_DISCLOSURE_PATTERNS:
            match = pattern.search(body)
            if match:
                # Extract surrounding context for the snippet
                start = max(0, match.start() - 50)
                end = min(len(body), match.end() + 150)
                snippet = body[start:end]
                if start > 0:
                    snippet = "..." + snippet
                if end < len(body):
                    snippet = snippet + "..."

                self.add_finding(
                    severity="medium",
                    title=f"Information disclosure ({description}) at {self._short_path(url)}",
                    description=(
                        f"The endpoint {url} exposes sensitive information in its "
                        f"response: {description}. This can reveal internal "
                        f"application structure, file paths, library versions, or "
                        f"credentials to an attacker."
                    ),
                    evidence={
                        "url": url,
                        "payload": "Standard GET request (no auth)",
                        "response_snippet": snippet,
                    },
                    remediation=(
                        "1. Disable debug mode and detailed error messages in production.\n"
                        "2. Implement a generic error handler that returns safe error "
                        "messages without internal details.\n"
                        "3. Remove stack traces, server versions, and internal paths "
                        "from API responses.\n"
                        "4. Use structured logging to capture details server-side "
                        "without exposing them to clients.\n"
                        "5. Review the endpoint to ensure it does not leak secrets, "
                        "tokens, or database connection strings."
                    ),
                    owasp_category="A05:2021 - Security Misconfiguration",
                    cvss_score=5.3,
                    affected_url=url,
                )
                # Report only the first disclosure pattern per endpoint to
                # avoid flooding findings.
                break

        # Check for common error pages that reveal framework information
        self._check_default_error_pages(url, resp)

    def _check_default_error_pages(self, url: str, resp: requests.Response) -> None:
        """Detect default framework error pages that reveal technology."""
        body_lower = resp.text.lower()
        detections: list[tuple[str, str]] = [
            ("werkzeug debugger", "Flask/Werkzeug debug console -- may allow remote code execution"),
            ("django debug page", "Django debug mode is active"),
            ("laravel", "Laravel framework error page"),
            ("express", "Express.js default error page"),
            ("whitelabel error page", "Spring Boot Whitelabel error page"),
        ]

        for signature, description in detections:
            if signature in body_lower and resp.status_code >= 400:
                self.add_finding(
                    severity="medium" if "werkzeug" not in signature else "critical",
                    title=f"Default framework error page detected at {self._short_path(url)}",
                    description=(
                        f"The endpoint {url} returned a default framework error "
                        f"page: {description}. This reveals the technology stack "
                        f"and may expose additional debugging functionality."
                    ),
                    evidence={
                        "url": url,
                        "payload": "Standard GET request",
                        "response_snippet": resp.text[:300],
                    },
                    remediation=(
                        "1. Disable debug mode in production environments.\n"
                        "2. Implement custom error pages that do not reveal "
                        "framework or technology details.\n"
                        "3. Flask: set app.debug = False and remove Werkzeug debugger.\n"
                        "4. Django: set DEBUG = False in settings.py.\n"
                        "5. Spring: customize the error controller."
                    ),
                    owasp_category="A05:2021 - Security Misconfiguration",
                    cvss_score=7.5 if "werkzeug" in signature else 4.0,
                    affected_url=url,
                )
                break

    # ------------------------------------------------------------------
    # URL helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_url(raw_url: str, base_url: str) -> Optional[str]:
        """Resolve a potentially relative URL against *base_url*.

        Returns None if the URL cannot be resolved or looks like a
        template placeholder.
        """
        # Skip template / interpolation placeholders
        if "${" in raw_url or "{{" in raw_url or raw_url.startswith("#"):
            return None

        if raw_url.startswith(("http://", "https://")):
            return raw_url

        if raw_url.startswith("/"):
            return urljoin(base_url, raw_url)

        # Relative path
        return urljoin(base_url, raw_url)

    @staticmethod
    def _is_same_origin(url: str, base_url: str) -> bool:
        """Return True if *url* has the same origin as *base_url*."""
        return urlparse(url).netloc == urlparse(base_url).netloc

    @staticmethod
    def _short_path(url: str) -> str:
        """Return just the path component of a URL for concise titles."""
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query[:30]}"
        return path
