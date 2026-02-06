"""
HackerPA Engine - Access Control / BOLA / BFLA / IDOR Scanner

Tests for broken access control vulnerabilities -- the #1 risk in the
OWASP Top 10 (A01:2021).  Specifically:

  1. HTTP Method Tampering   -- unexpected methods accepted on endpoints
  2. IDOR                    -- insecure direct object references via ID swapping
  3. Authentication Bypass   -- bypassing 401/403 with crafted headers or tokens
  4. Privilege Escalation    -- admin/internal endpoints accessible without auth
  5. Forced Browsing         -- authenticated-only pages reachable directly

All tests are **read-only**.  PUT/DELETE probes only inspect the status
code and never send a destructive body payload.
"""

import re
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from engine.scanners.base_scanner import BaseScanner
from engine.orchestrator import firebase_client


# ====================================================================
# Constants
# ====================================================================

# GraphQL introspection query (read-only)
_GRAPHQL_INTROSPECTION = '{"query":"{ __schema { types { name } } }"}'

# HTTP methods to attempt during method-tampering tests.
# The list is intentionally small to keep the scanner non-destructive.
_ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

# IDs to substitute when testing IDOR.  Chosen to cover boundary
# values and neighbouring-object scenarios.
_IDOR_TEST_IDS = ["0", "1", "2", "999", "99999"]

# Regex that matches a numeric ID segment in a URL path, e.g.
# ``/api/users/42`` or ``/orders/12345/details``.
_NUMERIC_ID_RE = re.compile(r"(/\d+)(?=/|$)")

# Headers and token values used for authentication bypass probes
_AUTH_BYPASS_HEADERS: list[dict[str, str]] = [
    {},                                                          # no auth header at all
    {"Authorization": ""},                                       # empty
    {"Authorization": "Bearer null"},                            # literal null
    {"Authorization": "Bearer undefined"},                       # literal undefined
    {"Authorization": "Bearer "},                                # space only
    {"Authorization": "Basic YWRtaW46YWRtaW4="},                # admin:admin base64
    {"X-Original-URL": "/admin"},                                # Nginx/IIS path override
    {"X-Rewrite-URL": "/admin"},                                 # URL rewrite override
    {"X-Custom-IP-Authorization": "127.0.0.1"},                  # IP-based bypass
    {"X-Forwarded-For": "127.0.0.1"},                            # IP spoof
    {"X-Forwarded-Host": "localhost"},                           # host spoof
    {"X-Real-IP": "127.0.0.1"},                                 # real IP override
]

# Privileged / admin API endpoints to probe
_PRIVILEGED_PATHS: list[str] = [
    "/api/admin",
    "/api/v1/admin",
    "/api/v2/admin",
    "/admin/api",
    "/admin",
    "/api/users",
    "/api/v1/users",
    "/api/config",
    "/api/v1/config",
    "/api/settings",
    "/api/v1/settings",
    "/api/debug",
    "/api/internal",
    "/api/v1/internal",
    "/internal",
    "/internal/api",
    "/management",
    "/api/logs",
    "/api/metrics",
    "/api/env",
    "/graphql",
]

# Pages that typically require authentication (forced browsing)
_AUTH_REQUIRED_PATHS: list[str] = [
    "/dashboard",
    "/profile",
    "/settings",
    "/admin",
    "/admin/dashboard",
    "/account",
    "/account/settings",
    "/api/me",
    "/api/whoami",
    "/api/user/profile",
    "/api/user/me",
    "/api/account",
    "/api/dashboard",
    "/user/profile",
    "/user/settings",
    "/my-account",
    "/member",
    "/members",
    "/panel",
]

# Login-redirect indicators (case-insensitive substrings in response
# body or Location header) that tell us the page correctly redirects
# unauthenticated users.
_LOGIN_REDIRECT_INDICATORS = [
    "login", "signin", "sign-in", "sign_in", "auth",
    "unauthorized", "403", "forbidden",
]

# OWASP category constant used throughout this scanner.
_OWASP = "A01:2021 - Broken Access Control"


class AccessControlScanner(BaseScanner):
    """Broken access control scanner (BOLA / BFLA / IDOR).

    Discovers endpoints through page analysis, crawl data (when
    available in Firestore), and common-path probing, then executes
    five categories of access-control tests.
    """

    scanner_name = "access_control_scanner"

    def run(self) -> None:
        self.log("info", f"Starting access control scan for {self.base_url}")

        # Load crawl data from Firestore if a previous crawler populated it.
        self.crawl_data: dict = self._load_crawl_data()

        # ------------------------------------------------------------------
        # 1. Build the set of endpoints to test
        # ------------------------------------------------------------------
        endpoints: dict[str, str] = {}  # url -> discovery_method

        # a) Crawl-data API endpoints
        for ep in self.crawl_data.get("apiEndpoints", []):
            url = self._resolve(ep)
            if url:
                endpoints[url] = "crawl_data_api"

        # b) Crawl-data pages
        for page in self.crawl_data.get("pages", []):
            url = self._resolve(page)
            if url:
                endpoints[url] = "crawl_data_page"

        # c) Fetch main page and extract links / API references
        main_resp = self.make_request(self.base_url)
        if main_resp is None:
            self.log("error", f"Could not reach {self.base_url} - aborting access control scan")
            return

        parsed = self._extract_links(main_resp.text)
        for url in parsed:
            if url not in endpoints:
                endpoints[url] = "parsed_from_source"

        self.log(
            "info",
            f"Collected {len(endpoints)} endpoint(s) from crawl data + page parsing",
        )

        # ------------------------------------------------------------------
        # 2. Run test categories
        # ------------------------------------------------------------------

        # 2a. HTTP Method Tampering
        self.log("info", "Phase 1/5: HTTP method tampering")
        self._test_method_tampering(endpoints)

        # 2b. IDOR
        self.log("info", "Phase 2/5: IDOR testing")
        self._test_idor(endpoints)

        # 2c. Authentication Bypass
        self.log("info", "Phase 3/5: Authentication bypass")
        self._test_auth_bypass(endpoints)

        # 2d. Privilege Escalation Paths
        self.log("info", "Phase 4/5: Privilege escalation paths")
        self._test_privilege_escalation()

        # 2e. Forced Browsing
        self.log("info", "Phase 5/5: Forced browsing")
        self._test_forced_browsing()

        self.log("info", "Access control scan complete")

    # ==================================================================
    # Data loading helpers
    # ==================================================================

    def _load_crawl_data(self) -> dict:
        """Attempt to load crawl data from Firestore for this scan."""
        try:
            doc = firebase_client.db.collection("scans").document(self.scan_id).get()
            if doc.exists:
                data = doc.to_dict()
                return data.get("crawlData", {}) or {}
        except Exception:
            self.log("warning", "Could not load crawl data from Firestore")
        return {}

    def _resolve(self, raw: str) -> Optional[str]:
        """Resolve a raw path or URL to a full URL on the target."""
        if not raw:
            return None
        if raw.startswith(("http://", "https://")):
            # Only keep same-origin URLs
            if urlparse(raw).netloc == urlparse(self.base_url).netloc:
                return raw
            return None
        return urljoin(self.base_url, raw)

    def _extract_links(self, html: str) -> list[str]:
        """Extract same-origin links and API references from HTML."""
        patterns = [
            re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'["\'](/api/[^"\'?\s]+)["\']', re.IGNORECASE),
        ]
        found: set[str] = set()
        base_host = urlparse(self.base_url).netloc

        for pattern in patterns:
            for match in pattern.finditer(html):
                raw = match.group(1)
                if raw.startswith("#") or raw.startswith("javascript:"):
                    continue
                resolved = urljoin(self.base_url, raw)
                if urlparse(resolved).netloc == base_host:
                    found.add(resolved)

        return list(found)

    # ==================================================================
    # URL / response helpers
    # ==================================================================

    @staticmethod
    def _short_path(url: str) -> str:
        """Return just the path portion of a URL for concise titles."""
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query[:40]}"
        return path

    @staticmethod
    def _is_data_response(resp: requests.Response) -> bool:
        """Return True if the response looks like it contains real data."""
        ct = resp.headers.get("Content-Type", "")
        body = resp.text.strip()
        if "application/json" in ct and len(body) > 20:
            return True
        if "application/xml" in ct and len(body) > 20:
            return True
        if "text/html" in ct and len(body) > 200:
            return True
        return False

    @staticmethod
    def _looks_like_login_redirect(resp: requests.Response) -> bool:
        """Return True if the response appears to be a redirect to a
        login page or an explicit 401/403 rejection."""
        if resp.status_code in (401, 403):
            return True
        # 3xx redirect whose Location contains login-like keywords
        if 300 <= resp.status_code < 400:
            location = resp.headers.get("Location", "").lower()
            if any(kw in location for kw in _LOGIN_REDIRECT_INDICATORS):
                return True
        # Body heuristic (e.g. single-page app that renders a login form)
        body_lower = resp.text[:2000].lower()
        login_signals = sum(
            1 for kw in ("sign in", "log in", "login", "signin", "unauthorized")
            if kw in body_lower
        )
        if login_signals >= 2:
            return True
        return False

    # ==================================================================
    # 1. HTTP Method Tampering
    # ==================================================================

    def _test_method_tampering(self, endpoints: dict[str, str]) -> None:
        """For each endpoint, check whether unexpected HTTP methods are
        accepted and return meaningful data."""

        tested: set[str] = set()

        for url in list(endpoints.keys())[:50]:  # cap to avoid excessive requests
            path = urlparse(url).path
            if path in tested:
                continue
            tested.add(path)

            # Determine the "expected" method by issuing a GET first.
            baseline = self.make_request(url, allow_redirects=False)
            if baseline is None:
                continue

            # Only test endpoints that are alive
            if baseline.status_code in (404, 502, 503):
                continue

            # If GET works (200), try state-changing methods
            if baseline.status_code == 200:
                for method in ("POST", "PUT", "DELETE", "PATCH"):
                    resp = self.make_request(url, method=method, allow_redirects=False)
                    if resp is None:
                        continue
                    if resp.status_code == 200 and self._is_data_response(resp):
                        self._report_method_tampering(url, method, resp)
                        break  # one finding per endpoint is enough

            # If GET is blocked (401/403/405), try other methods
            elif baseline.status_code in (401, 403, 405):
                for method in ("POST", "PUT", "PATCH", "OPTIONS", "HEAD"):
                    resp = self.make_request(url, method=method, allow_redirects=False)
                    if resp is None:
                        continue
                    if resp.status_code == 200 and self._is_data_response(resp):
                        self._report_method_tampering(url, method, resp)
                        break

    def _report_method_tampering(
        self, url: str, method: str, resp: requests.Response
    ) -> None:
        remediation = self.get_remediation_with_code(
            "auth",
            "1. Explicitly define allowed HTTP methods for each route and "
            "reject all others with 405 Method Not Allowed.\n"
            "2. Ensure authorization checks are applied regardless of the "
            "HTTP method used.\n"
            "3. In Express: use route-specific methods (app.get, app.post) "
            "instead of app.all().\n"
            "4. In Django: use the @require_http_methods decorator.\n"
            "5. In Spring: specify method= on @RequestMapping.",
        )
        self.add_finding(
            severity="medium",
            title=f"HTTP method tampering accepted: {method} {self._short_path(url)}",
            description=(
                f"The endpoint {url} accepts the {method} method and returns "
                f"a data response (HTTP {resp.status_code}).  If access control "
                f"logic only protects certain methods (e.g. GET), an attacker "
                f"could use an alternative method to bypass restrictions or "
                f"trigger unintended side effects."
            ),
            evidence=f"Request: {method} {url}\nHTTP {resp.status_code}\nBody (first 300 chars): {resp.text[:300]}",
            remediation=remediation,
            owasp_category=_OWASP,
            cvss_score=5.3,
            affected_url=url,
        )

    # ==================================================================
    # 2. IDOR (Insecure Direct Object Reference)
    # ==================================================================

    def _test_idor(self, endpoints: dict[str, str]) -> None:
        """Find endpoints with numeric IDs in the path and try swapping
        them to detect insecure direct object references."""

        tested_patterns: set[str] = set()

        for url in list(endpoints.keys()):
            match = _NUMERIC_ID_RE.search(urlparse(url).path)
            if not match:
                continue

            original_id = match.group(1).lstrip("/")
            path = urlparse(url).path

            # Deduplicate by path pattern (replace the ID with a placeholder)
            pattern_key = _NUMERIC_ID_RE.sub("/{ID}", path)
            if pattern_key in tested_patterns:
                continue
            tested_patterns.add(pattern_key)

            # Get the baseline response for the original ID
            baseline = self.make_request(url)
            if baseline is None or baseline.status_code != 200:
                continue

            baseline_body = baseline.text.strip()
            if len(baseline_body) < 10:
                continue  # too short to be meaningful data

            # Try alternative IDs
            for test_id in _IDOR_TEST_IDS:
                if test_id == original_id:
                    continue

                test_url = url.replace(f"/{original_id}", f"/{test_id}", 1)
                resp = self.make_request(test_url)
                if resp is None:
                    continue

                if resp.status_code == 200 and len(resp.text.strip()) > 10:
                    # Different data returned for a different ID => IDOR
                    if resp.text.strip() != baseline_body:
                        self._report_idor(url, original_id, test_url, test_id, resp)
                        break  # one finding per pattern

    def _report_idor(
        self,
        original_url: str,
        original_id: str,
        test_url: str,
        test_id: str,
        resp: requests.Response,
    ) -> None:
        remediation = self.get_remediation_with_code(
            "auth",
            "1. Always verify that the authenticated user is authorized to "
            "access the requested resource (object-level authorization).\n"
            "2. Use indirect references (UUIDs, opaque tokens) instead of "
            "sequential integers for object IDs.\n"
            "3. In Express: middleware that checks req.user.id against the "
            "resource owner before returning data.\n"
            "4. In Django: filter querysets by the current user "
            "(Model.objects.filter(owner=request.user)).\n"
            "5. Implement automated IDOR tests in your CI/CD pipeline.",
        )
        self.add_finding(
            severity="high",
            title=f"IDOR: different data returned for swapped ID at {self._short_path(original_url)}",
            description=(
                f"The endpoint {original_url} (ID={original_id}) was accessed "
                f"with ID={test_id} at {test_url} and returned a different, "
                f"non-empty response (HTTP {resp.status_code}).  This indicates "
                f"that object-level authorization is missing and any user can "
                f"access arbitrary records by changing the numeric identifier "
                f"in the URL (Insecure Direct Object Reference / BOLA)."
            ),
            evidence=(
                f"Original: GET {original_url} (ID={original_id})\n"
                f"Tampered: GET {test_url} (ID={test_id})\n"
                f"HTTP {resp.status_code}\n"
                f"Body (first 300 chars): {resp.text[:300]}"
            ),
            remediation=remediation,
            owasp_category=_OWASP,
            cvss_score=7.5,
            affected_url=original_url,
        )

    # ==================================================================
    # 3. Authentication Bypass
    # ==================================================================

    def _test_auth_bypass(self, endpoints: dict[str, str]) -> None:
        """For endpoints that return 401/403, try various header-based
        authentication bypass techniques."""

        tested: set[str] = set()

        for url in list(endpoints.keys())[:50]:
            path = urlparse(url).path
            if path in tested:
                continue
            tested.add(path)

            # First check if the endpoint requires auth
            baseline = self.make_request(url, allow_redirects=False)
            if baseline is None:
                continue

            if baseline.status_code not in (401, 403):
                continue  # not auth-protected, skip

            # Try each bypass header set
            for bypass_headers in _AUTH_BYPASS_HEADERS:
                resp = self.make_request(
                    url,
                    headers=bypass_headers,
                    allow_redirects=False,
                )
                if resp is None:
                    continue

                if resp.status_code == 200 and self._is_data_response(resp):
                    header_desc = (
                        ", ".join(f"{k}: {v}" for k, v in bypass_headers.items())
                        if bypass_headers
                        else "(no auth headers)"
                    )
                    self._report_auth_bypass(url, header_desc, resp)
                    break  # one bypass per endpoint is enough

    def _report_auth_bypass(
        self, url: str, bypass_desc: str, resp: requests.Response
    ) -> None:
        remediation = self.get_remediation_with_code(
            "auth",
            "1. CRITICAL: Validate authentication tokens server-side on "
            "every request -- never trust client-supplied headers alone.\n"
            "2. Reject requests with missing, empty, or malformed "
            "Authorization headers with 401.\n"
            "3. Do not use X-Original-URL or X-Rewrite-URL for routing "
            "decisions -- or strip them at the reverse proxy.\n"
            "4. Ensure IP-based allow-lists cannot be spoofed via "
            "X-Forwarded-For / X-Real-IP headers.\n"
            "5. Implement centralized authentication middleware that "
            "runs before any business logic.",
        )
        self.add_finding(
            severity="critical",
            title=f"Authentication bypass at {self._short_path(url)}",
            description=(
                f"The endpoint {url} normally returns 401/403 but returned "
                f"HTTP {resp.status_code} with data when accessed with the "
                f"following bypass technique: {bypass_desc}.  An attacker "
                f"can exploit this to access protected resources without "
                f"valid credentials."
            ),
            evidence=(
                f"Baseline: 401/403 (normal request)\n"
                f"Bypass headers: {bypass_desc}\n"
                f"Result: HTTP {resp.status_code}\n"
                f"Body (first 300 chars): {resp.text[:300]}"
            ),
            remediation=remediation,
            owasp_category=_OWASP,
            cvss_score=9.8,
            affected_url=url,
        )

    # ==================================================================
    # 4. Privilege Escalation Paths
    # ==================================================================

    def _test_privilege_escalation(self) -> None:
        """Probe common admin/internal endpoints without authentication."""

        for path in _PRIVILEGED_PATHS:
            url = self.base_url.rstrip("/") + path

            # Special case: GraphQL introspection
            if path == "/graphql":
                self._test_graphql_introspection(url)
                continue

            resp = self.make_request(url, allow_redirects=False)
            if resp is None:
                continue

            if resp.status_code in (404, 405, 502, 503):
                continue

            # If the endpoint returns 200 with real data, that's a problem
            if resp.status_code == 200 and self._is_data_response(resp):
                is_admin = any(
                    kw in path.lower()
                    for kw in ("admin", "internal", "management", "debug")
                )
                severity = "high" if is_admin else "medium"
                cvss = 8.0 if is_admin else 5.3

                remediation = self.get_remediation_with_code(
                    "auth",
                    "1. Require authentication and admin-level authorization "
                    "for all privileged endpoints.\n"
                    "2. Move admin/internal APIs to a separate service or "
                    "network segment not reachable from the public internet.\n"
                    "3. Implement role-based access control (RBAC) and verify "
                    "roles server-side on every request.\n"
                    "4. Return 404 (not 403) for admin paths to avoid "
                    "confirming their existence to attackers.\n"
                    "5. Audit all routes to ensure none are accidentally "
                    "left unprotected.",
                )
                self.add_finding(
                    severity=severity,
                    title=f"Privileged endpoint accessible without auth: {path}",
                    description=(
                        f"The endpoint {url} returned data (HTTP {resp.status_code}) "
                        f"without requiring authentication.  This path appears to be "
                        f"an administrative or internal endpoint that should be "
                        f"restricted.  An attacker can access it directly to view "
                        f"sensitive configuration, user data, or internal state."
                    ),
                    evidence=(
                        f"Request: GET {url}\n"
                        f"HTTP {resp.status_code}\n"
                        f"Content-Type: {resp.headers.get('Content-Type', 'N/A')}\n"
                        f"Body (first 300 chars): {resp.text[:300]}"
                    ),
                    remediation=remediation,
                    owasp_category=_OWASP,
                    cvss_score=cvss,
                    affected_url=url,
                )

    def _test_graphql_introspection(self, url: str) -> None:
        """Send a GraphQL introspection query and report if it succeeds."""
        resp = self.make_request(
            url,
            method="POST",
            headers={"Content-Type": "application/json"},
            data=_GRAPHQL_INTROSPECTION,
            allow_redirects=False,
        )
        if resp is None:
            return

        if resp.status_code == 200 and "__schema" in resp.text:
            remediation = self.get_remediation_with_code(
                "auth",
                "1. Disable GraphQL introspection in production.\n"
                "   - Apollo Server: introspection: false\n"
                "   - graphql-yoga: set introspection to false in config\n"
                "   - Django Graphene: set GRAPHENE = {'INTROSPECTION': False}\n"
                "2. Require authentication for the /graphql endpoint.\n"
                "3. Implement field-level authorization to ensure users "
                "can only query data they are allowed to see.",
            )
            self.add_finding(
                severity="high",
                title="GraphQL introspection enabled without authentication",
                description=(
                    f"The GraphQL endpoint at {url} allows introspection "
                    f"queries without authentication.  Introspection exposes "
                    f"the entire API schema including all types, fields, "
                    f"queries, and mutations.  An attacker can use this to "
                    f"map the full attack surface of the API."
                ),
                evidence=(
                    f"Request: POST {url}\n"
                    f'Payload: {_GRAPHQL_INTROSPECTION}\n'
                    f"HTTP {resp.status_code}\n"
                    f"Body (first 300 chars): {resp.text[:300]}"
                ),
                remediation=remediation,
                owasp_category=_OWASP,
                cvss_score=5.3,
                affected_url=url,
            )

    # ==================================================================
    # 5. Forced Browsing
    # ==================================================================

    def _test_forced_browsing(self) -> None:
        """Check if pages that should require authentication are
        accessible without credentials."""

        for path in _AUTH_REQUIRED_PATHS:
            url = self.base_url.rstrip("/") + path

            resp = self.make_request(url, allow_redirects=False)
            if resp is None:
                continue

            if resp.status_code in (404, 405, 502, 503):
                continue

            # A proper app should redirect to login or return 401/403.
            if self._looks_like_login_redirect(resp):
                continue  # correctly protected

            # If 200 with content and NOT a login page, flag it.
            if resp.status_code == 200 and self._is_data_response(resp):
                # Extra heuristic: check if body is just a generic landing
                # page (e.g. SPA shell) or contains actual user data.
                body_lower = resp.text[:3000].lower()
                has_user_content = any(
                    kw in body_lower
                    for kw in (
                        "dashboard", "profile", "settings", "account",
                        "welcome", "email", "username", "user_id",
                        '"name"', '"email"', '"role"',
                    )
                )
                if not has_user_content:
                    continue  # likely a generic SPA shell, not a real leak

                is_api = path.startswith("/api/")
                severity = "high" if is_api else "medium"
                cvss = 7.5 if is_api else 5.3

                remediation = self.get_remediation_with_code(
                    "auth",
                    "1. Implement authentication middleware that runs before "
                    "rendering any protected page or API response.\n"
                    "2. For SPAs: verify the auth token on the server-side "
                    "API call, not just in client-side route guards.\n"
                    "3. Return 302 redirect to /login for unauthenticated "
                    "requests to protected pages.\n"
                    "4. Return 401 for unauthenticated API requests.\n"
                    "5. Ensure server-rendered pages do not include user "
                    "data in the initial HTML for unauthenticated requests.",
                )
                self.add_finding(
                    severity=severity,
                    title=f"Forced browsing: protected page accessible at {path}",
                    description=(
                        f"The page at {url} appears to be an authenticated-only "
                        f"resource (e.g. dashboard, profile, settings) but it "
                        f"returned content (HTTP {resp.status_code}) without "
                        f"requiring authentication.  An attacker can navigate "
                        f"directly to this URL to access potentially sensitive "
                        f"user data or application functionality."
                    ),
                    evidence=(
                        f"Request: GET {url}\n"
                        f"HTTP {resp.status_code}\n"
                        f"Content-Type: {resp.headers.get('Content-Type', 'N/A')}\n"
                        f"Body (first 300 chars): {resp.text[:300]}"
                    ),
                    remediation=remediation,
                    owasp_category=_OWASP,
                    cvss_score=cvss,
                    affected_url=url,
                )

            # Handle 3xx redirects that do NOT go to a login page
            elif 300 <= resp.status_code < 400:
                location = resp.headers.get("Location", "")
                if location and not any(
                    kw in location.lower() for kw in _LOGIN_REDIRECT_INDICATORS
                ):
                    # Redirect goes somewhere other than login -- could be
                    # an open redirect or an unprotected page.  Follow it
                    # once to see what we get.
                    follow_resp = self.make_request(
                        urljoin(url, location), allow_redirects=False
                    )
                    if (
                        follow_resp
                        and follow_resp.status_code == 200
                        and self._is_data_response(follow_resp)
                        and not self._looks_like_login_redirect(follow_resp)
                    ):
                        self.add_finding(
                            severity="medium",
                            title=f"Forced browsing via redirect: {path} -> {self._short_path(location)}",
                            description=(
                                f"The path {url} redirects to {location} which "
                                f"returns content without authentication.  The "
                                f"redirect does not point to a login page, "
                                f"suggesting the protected content may be "
                                f"accessible indirectly."
                            ),
                            evidence=(
                                f"Request: GET {url}\n"
                                f"Redirect: {resp.status_code} -> {location}\n"
                                f"Final: HTTP {follow_resp.status_code}\n"
                                f"Body (first 300 chars): {follow_resp.text[:300]}"
                            ),
                            remediation=(
                                "1. Ensure redirects from protected pages always "
                                "lead to the login page.\n"
                                "2. Validate redirect targets against an allow-list.\n"
                                "3. Do not expose protected content at any URL "
                                "reachable without authentication."
                            ),
                            owasp_category=_OWASP,
                            cvss_score=5.3,
                            affected_url=url,
                        )
