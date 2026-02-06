"""
HackerPA Engine - Subdomain Discovery Scanner

Discovers subdomains that may be forgotten or misconfigured (dev, staging,
test environments) using DNS brute-forcing and certificate transparency logs.
"""

import socket
from urllib.parse import urlparse

import requests

from engine.scanners.base_scanner import BaseScanner


# Common subdomains to check (especially dangerous for vibe coders)
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dev", "develop", "development",
    "staging", "stage", "stg",
    "test", "testing", "qa",
    "uat", "preprod", "pre-prod", "pre",
    "demo", "sandbox", "beta", "alpha",
    "admin", "administrator", "panel",
    "api", "api-dev", "api-staging", "api-test",
    "app", "app-dev", "app-staging",
    "cdn", "static", "assets", "media", "images",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "jenkins", "ci", "cd", "deploy", "build",
    "git", "gitlab", "github", "bitbucket",
    "grafana", "prometheus", "kibana", "elastic",
    "vpn", "ssh", "remote",
    "internal", "intranet", "extranet",
    "old", "legacy", "backup", "bak",
    "portal", "dashboard", "console",
    "docs", "doc", "documentation", "wiki",
    "blog", "cms", "wordpress", "wp",
    "shop", "store", "ecommerce",
    "auth", "login", "sso", "oauth",
    "payment", "pay", "checkout",
    "socket", "ws", "websocket", "realtime",
    "graphql", "rest",
    "monitoring", "status", "health",
    "n8n", "airflow", "metabase", "supabase",
]


class SubdomainScanner(BaseScanner):
    scanner_name = "subdomain_scanner"

    def run(self) -> None:
        parsed = urlparse(self.base_url)
        base_domain = parsed.hostname or self.domain

        # Remove www. prefix if present to get the root domain
        if base_domain.startswith("www."):
            base_domain = base_domain[4:]

        self.log("info", f"Discovering subdomains for {base_domain}")

        found_subdomains = []

        # Method 1: DNS brute-force
        dns_results = self._dns_bruteforce(base_domain)
        found_subdomains.extend(dns_results)

        # Method 2: Certificate Transparency logs (via crt.sh)
        ct_results = self._check_certificate_transparency(base_domain)
        found_subdomains.extend(ct_results)

        # Deduplicate
        unique_subdomains = list(set(found_subdomains))

        if unique_subdomains:
            self.log("info", f"Found {len(unique_subdomains)} subdomains")

            # Check each discovered subdomain for issues
            for subdomain in unique_subdomains:
                self._analyze_subdomain(subdomain, base_domain)
        else:
            self.log("info", "No additional subdomains discovered")

        self.log("info", "Subdomain discovery complete")

    def _dns_bruteforce(self, base_domain: str) -> list[str]:
        """Try common subdomain prefixes via DNS resolution."""
        found = []
        for prefix in COMMON_SUBDOMAINS:
            subdomain = f"{prefix}.{base_domain}"
            try:
                socket.gethostbyname(subdomain)
                found.append(subdomain)
                self.log("info", f"Subdomain found (DNS): {subdomain}")
            except socket.gaierror:
                pass
        return found

    def _check_certificate_transparency(self, base_domain: str) -> list[str]:
        """Query crt.sh for certificate transparency logs."""
        found = []
        try:
            resp = self.make_request(
                f"https://crt.sh/?q=%.{base_domain}&output=json",
                timeout=15,
            )
            if resp and resp.status_code == 200:
                entries = resp.json()
                for entry in entries[:100]:  # Limit to first 100
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        clean = line.strip().lower()
                        if clean and "*" not in clean and clean not in found:
                            found.append(clean)
                self.log("info", f"Found {len(found)} subdomains from CT logs")
        except Exception as e:
            self.log("warning", f"CT log query failed: {e}")
        return found

    def _analyze_subdomain(self, subdomain: str, base_domain: str) -> None:
        """Analyze a discovered subdomain for security issues."""
        # Check if it's a dev/staging/test environment
        risky_prefixes = ["dev", "staging", "stage", "test", "qa", "uat", "demo",
                          "sandbox", "beta", "preprod", "internal", "old", "legacy", "backup"]

        is_risky = any(subdomain.startswith(f"{p}.") for p in risky_prefixes)

        # Try to reach the subdomain
        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
            response = self.make_request(url, timeout=5)
            if response is not None:
                severity = "high" if is_risky else "info"
                title = (
                    f"Ambiente de desenvolvimento/teste exposto: {subdomain}"
                    if is_risky
                    else f"Subdominio ativo descoberto: {subdomain}"
                )
                description = (
                    f"O subdominio '{subdomain}' esta acessivel publicamente. "
                    f"Ambientes de dev/staging frequentemente tem seguranca reduzida, "
                    f"debug ativado, e podem expor dados reais."
                    if is_risky
                    else f"O subdominio '{subdomain}' esta ativo e respondendo."
                )

                self.add_finding(
                    severity=severity,
                    title=title,
                    description=description,
                    evidence={
                        "url": url,
                        "response_snippet": f"Status: {response.status_code}, Server: {response.headers.get('Server', 'unknown')}",
                    },
                    remediation=(
                        "1. Proteja ambientes de dev/staging com autenticacao (HTTP Basic Auth ou VPN).\n"
                        "2. Nao use dados reais em ambientes de teste.\n"
                        "3. Mantenha debug desativado mesmo em staging.\n"
                        "4. Use DNS privado ou VPN para acessar ambientes internos."
                        if is_risky
                        else "Verifique se este subdominio precisa estar publico e se esta adequadamente protegido."
                    ),
                    owasp_category="A05:2021 - Security Misconfiguration",
                    cvss_score=7.0 if is_risky else 2.0,
                    affected_url=url,
                )
                break  # Found on one scheme, no need to check the other
