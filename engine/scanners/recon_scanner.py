"""
HackerPA Engine - Reconnaissance Scanner

Performs initial reconnaissance: technology detection, subdomain discovery,
HTTP fingerprinting, and information gathering.
"""

import re
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from engine.orchestrator import firebase_client
from engine.scanners.base_scanner import BaseScanner


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
                    firebase_client.save_detected_tech(self.scan_id, unique_tech)
            except Exception:
                self.log("warning", "Could not save detected tech")
            self.log("info", f"Detected technologies: {', '.join(unique_tech)}")
            self.add_finding(
                severity="info",
                title="Tecnologias detectadas",
                description=f"As seguintes tecnologias foram identificadas: {', '.join(unique_tech)}. "
                            f"Conhecer o stack permite buscar CVEs especificos.",
                evidence={
                    "url": self.base_url,
                    "response_snippet": f"Technologies: {', '.join(unique_tech)}",
                },
                remediation="Minimize a exposicao de informacoes sobre seu stack. Remova headers como X-Powered-By e Server.",
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
                        title="WordPress XML-RPC ativo",
                        description="O XML-RPC do WordPress esta ativo. Pode ser usado para ataques de brute force e DDoS amplification.",
                        evidence={"url": url, "response_snippet": f"Status: {response.status_code}"},
                        remediation="Desabilite XML-RPC se nao for necessario. Adicione: add_filter('xmlrpc_enabled', '__return_false');",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        cvss_score=5.0,
                        affected_url=url,
                    )
                elif tech_name == "GraphQL":
                    self.add_finding(
                        severity="medium",
                        title="Endpoint GraphQL descoberto",
                        description="Endpoint GraphQL acessivel. Pode permitir introspection queries que revelam todo o schema da API.",
                        evidence={"url": url, "response_snippet": f"Status: {response.status_code}"},
                        remediation="Desabilite GraphQL introspection em producao. Implemente rate limiting e autenticacao.",
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
                    title=f"Metodos HTTP perigosos habilitados: {', '.join(found_dangerous)}",
                    description=f"O servidor permite os metodos HTTP: {allowed}. "
                                f"Metodos como TRACE e PUT podem ser explorados.",
                    evidence={"url": self.base_url, "response_snippet": f"Allow: {allowed}"},
                    remediation="Desabilite metodos HTTP desnecessarios no web server. Permita apenas GET, POST, HEAD.",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    cvss_score=4.0,
                    affected_url=self.base_url,
                )

    def _check_cookies(self, response) -> None:
        """Check cookie security flags."""
        for cookie in response.cookies:
            issues = []

            if not cookie.secure:
                issues.append("Secure flag ausente")
            if "httponly" not in str(cookie._rest).lower():
                issues.append("HttpOnly flag ausente")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("SameSite ausente")

            if issues:
                self.add_finding(
                    severity="medium" if "Secure" in str(issues) else "low",
                    title=f"Cookie inseguro: {cookie.name}",
                    description=f"O cookie '{cookie.name}' tem problemas de seguranca: {', '.join(issues)}. "
                                f"Isso pode permitir roubo de sessao ou ataques CSRF.",
                    evidence={
                        "url": self.base_url,
                        "response_snippet": f"Cookie: {cookie.name}, Issues: {', '.join(issues)}",
                    },
                    remediation=self.get_remediation_with_code("cookies",
                        "Configure cookies com: Secure (apenas HTTPS), HttpOnly (inacessivel por JS), SameSite=Strict ou Lax."),
                    owasp_category="A05:2021 - Security Misconfiguration",
                    cvss_score=4.0,
                    affected_url=self.base_url,
                )
