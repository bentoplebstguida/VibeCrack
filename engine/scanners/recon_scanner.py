"""
VibeCrack Engine - Reconnaissance Scanner

Performs initial reconnaissance: technology detection, subdomain discovery,
HTTP fingerprinting, and information gathering.
"""

import re
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from engine.scanners.base_scanner import BaseScanner, _get_firebase


# Common technology signatures in headers and HTML
TECH_SIGNATURES = {
    # Headers-based detection
    "headers": {
        "X-Powered-By": {
            "Express": ("Node.js / Express", "medium"),
            "PHP": ("PHP", "medium"),
            "ASP.NET": ("ASP.NET", "medium"),
            "Next.js": ("Next.js", "low"),
            "Nuxt": ("Nuxt.js", "low"),
        },
        "Server": {
            "nginx": ("Nginx", "low"),
            "Apache": ("Apache", "low"),
            "cloudflare": ("Cloudflare", "info"),
            "Vercel": ("Vercel", "info"),
            "netlify": ("Netlify", "info"),
            "Microsoft-IIS": ("Microsoft IIS", "medium"),
        },
        "X-Generator": {
            "WordPress": ("WordPress", "medium"),
            "Drupal": ("Drupal", "medium"),
            "Joomla": ("Joomla", "medium"),
        },
    },
    # HTML meta/script-based detection
    "html_patterns": [
        (r"wp-content|wp-includes", "WordPress"),
        (r"__next|_next/static", "Next.js"),
        (r"__nuxt|_nuxt/", "Nuxt.js"),
        (r"ng-app|ng-controller|angular", "Angular"),
        (r"react|__REACT_DEVTOOLS", "React"),
        (r"vue\.|__VUE__", "Vue.js"),
        (r"svelte", "Svelte"),
        (r"laravel|csrf-token.*content", "Laravel"),
        (r"django|csrfmiddlewaretoken", "Django"),
        (r"rails|csrf-param", "Ruby on Rails"),
        (r"firebase|firebaseapp\.com", "Firebase"),
        (r"supabase", "Supabase"),
        (r"stripe\.js|js\.stripe\.com", "Stripe"),
        (r"recaptcha|grecaptcha", "Google reCAPTCHA"),
        (r"gtag|google-analytics|googletagmanager", "Google Analytics/GTM"),
        (r"hotjar|_hjSettings", "Hotjar"),
        (r"intercom", "Intercom"),
        (r"crisp\.chat", "Crisp Chat"),
        (r"zendesk", "Zendesk"),
    ],
}


class ReconScanner(BaseScanner):
    scanner_name = "recon_scanner"

    def run(self) -> None:
        self.log("info", f"Starting reconnaissance for {self.base_url}")

        response = self.make_request(self.base_url)
        if response is None:
            self.log("error", f"Could not reach {self.base_url}")
            return

        detected_tech = []

        # 1. Technology detection from headers
        header_tech = self._detect_from_headers(response.headers)
        detected_tech.extend(header_tech)

        # 2. Technology detection from HTML
        html_tech = self._detect_from_html(response.text)
        detected_tech.extend(html_tech)

        # 3. Check common paths for tech fingerprinting
        path_tech = self._detect_from_paths()
        detected_tech.extend(path_tech)

        # Save detected technologies for other scanners
        unique_tech = list(set(detected_tech))
        self.detected_tech = unique_tech
        if unique_tech:
            try:
                if self._data_store:
                    self._data_store.save_detected_tech(self.scan_id, unique_tech)
                else:
                    _get_firebase().save_detected_tech(self.scan_id, unique_tech)
            except Exception:
                self.log("warning", "Could not save detected tech")
            self.log("info", f"Detected technologies: {', '.join(unique_tech)}")
            self.add_finding(
                severity="info",
                title="Detected technologies",
                description=f"The following technologies were identified: {', '.join(unique_tech)}. "
                            f"Knowing the stack enables searching for specific CVEs.",
                evidence={
                    "url": self.base_url,
                    "response_snippet": f"Technologies: {', '.join(unique_tech)}",
                },
                remediation="Minimize stack information exposure. Remove headers like X-Powered-By and Server.",
                owasp_category="A05:2021 - Security Misconfiguration",
                affected_url=self.base_url,
            )

        # 4. Check HTTP methods
        self._check_http_methods()

        # 5. Check cookies security
        self._check_cookies(response)

        self.log("info", "Reconnaissance scan complete")

    def _detect_from_headers(self, headers) -> list[str]:
        """Detect technologies from HTTP response headers."""
        detected = []
        for header_name, signatures in TECH_SIGNATURES["headers"].items():
            value = headers.get(header_name, "")
            for sig, (tech_name, _) in signatures.items():
                if sig.lower() in value.lower():
                    detected.append(tech_name)
                    self.log("info", f"Detected from header {header_name}: {tech_name} ({value})")
        return detected

    def _detect_from_html(self, html: str) -> list[str]:
        """Detect technologies from HTML content patterns."""
        detected = []
        html_lower = html.lower()
        for pattern, tech_name in TECH_SIGNATURES["html_patterns"]:
            if re.search(pattern, html_lower, re.IGNORECASE):
                detected.append(tech_name)
                self.log("info", f"Detected from HTML pattern: {tech_name}")
        return detected

    def _detect_from_paths(self) -> list[str]:
        """Check common paths for technology fingerprinting."""
        detected = []
        tech_paths = [
            ("/wp-login.php", "WordPress"),
            ("/wp-admin/", "WordPress"),
            ("/xmlrpc.php", "WordPress XMLRPC"),
            ("/user/login", "Drupal"),
            ("/administrator/", "Joomla"),
            ("/api/health", "API Server"),
            ("/graphql", "GraphQL"),
            ("/_next/data/", "Next.js"),
        ]

        for path, tech_name in tech_paths:
            url = urljoin(self.base_url.rstrip("/") + "/", path.lstrip("/"))
            response = self.make_request(url, allow_redirects=False)
            if response and response.status_code in (200, 301, 302):
                detected.append(tech_name)
                self.log("info", f"Detected from path {path}: {tech_name}")

                # Special findings
                if tech_name == "WordPress XMLRPC":
                    self.add_finding(
                        severity="medium",
                        title="WordPress XML-RPC active",
                        description="WordPress XML-RPC is active. Can be used for brute force attacks and DDoS amplification.",
                        evidence={"url": url, "response_snippet": f"Status: {response.status_code}"},
                        remediation="Disable XML-RPC if not needed. Add: add_filter('xmlrpc_enabled', '__return_false');",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        cvss_score=5.0,
                        affected_url=url,
                    )
                elif tech_name == "GraphQL":
                    self.add_finding(
                        severity="medium",
                        title="GraphQL endpoint discovered",
                        description="GraphQL endpoint is accessible. May allow introspection queries that reveal the entire API schema.",
                        evidence={"url": url, "response_snippet": f"Status: {response.status_code}"},
                        remediation="Disable GraphQL introspection in production. Implement rate limiting and authentication.",
                        owasp_category="A01:2021 - Broken Access Control",
                        cvss_score=5.0,
                        affected_url=url,
                    )
        return detected

    def _check_http_methods(self) -> None:
        """Check if dangerous HTTP methods are enabled."""
        response = self.make_request(self.base_url, method="OPTIONS")
        if response and "Allow" in response.headers:
            allowed = response.headers["Allow"]
            dangerous = ["PUT", "DELETE", "TRACE", "CONNECT"]
            found_dangerous = [m for m in dangerous if m in allowed.upper()]
            if found_dangerous:
                self.add_finding(
                    severity="medium",
                    title=f"Dangerous HTTP methods enabled: {', '.join(found_dangerous)}",
                    description=f"The server allows HTTP methods: {allowed}. "
                                f"Methods like TRACE and PUT can be exploited.",
                    evidence={"url": self.base_url, "response_snippet": f"Allow: {allowed}"},
                    remediation="Disable unnecessary HTTP methods on the web server. Allow only GET, POST, HEAD.",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    cvss_score=4.0,
                    affected_url=self.base_url,
                )

    def _check_cookies(self, response) -> None:
        """Check cookie security flags."""
        for cookie in response.cookies:
            issues = []

            if not cookie.secure:
                issues.append("Secure flag missing")
            if "httponly" not in str(cookie._rest).lower():
                issues.append("HttpOnly flag missing")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("SameSite missing")

            if issues:
                self.add_finding(
                    severity="medium" if "Secure" in str(issues) else "low",
                    title=f"Insecure cookie: {cookie.name}",
                    description=f"The cookie '{cookie.name}' has security issues: {', '.join(issues)}. "
                                f"This may allow session hijacking or CSRF attacks.",
                    evidence={
                        "url": self.base_url,
                        "response_snippet": f"Cookie: {cookie.name}, Issues: {', '.join(issues)}",
                    },
                    remediation=self.get_remediation_with_code("cookies",
                        "Set cookies with: Secure (HTTPS only), HttpOnly (inaccessible to JS), SameSite=Strict or Lax."),
                    owasp_category="A05:2021 - Security Misconfiguration",
                    cvss_score=4.0,
                    affected_url=self.base_url,
                )
