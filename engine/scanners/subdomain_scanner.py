"""
HackerPA Engine - Subdomain Discovery Scanner

Discovers subdomains that may be forgotten or misconfigured (dev, staging,
test environments) using DNS brute-forcing and certificate transparency logs.
"""

import random
import socket
import string
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

        # Detect wildcard DNS before brute-forcing
        has_wildcard = self._detect_wildcard_dns(base_domain)

        found_subdomains = []

        if has_wildcard:
            self.log("warning", f"Wildcard DNS detected for {base_domain} - skipping DNS brute-force")
            self.add_finding(
                severity="info",
                title=f"Wildcard DNS detectado: *.{base_domain}",
                description=(
                    f"O dominio {base_domain} usa DNS wildcard, ou seja, qualquer subdominio "
                    f"(ex: xyz123.{base_domain}) resolve para um IP. Isso e comum em "
                    f"plataformas como Cloud Run, Vercel, Netlify, etc. "
                    f"A enumeracao de subdominios via DNS nao e eficaz neste caso."
                ),
                evidence={"url": f"*.{base_domain}"},
                remediation="Wildcard DNS e normal para plataformas cloud. Nenhuma acao necessaria.",
                owasp_category="A05:2021 - Security Misconfiguration",
                cvss_score=0.0,
                affected_url=self.base_url,
            )
        else:
            # Method 1: DNS brute-force (only when no wildcard)
            dns_results = self._dns_bruteforce(base_domain)
            found_subdomains.extend(dns_results)

        # Method 2: Certificate Transparency logs (via crt.sh)
        ct_results = self._check_certificate_transparency(base_domain)
        found_subdomains.extend(ct_results)

        # Deduplicate
        unique_subdomains = list(set(found_subdomains))

        if unique_subdomains:
            self.log("info", f"Found {len(unique_subdomains)} subdomains")

            # Check each discovered subdomain for issues (limit to avoid DoS)
            for subdomain in unique_subdomains[:30]:
                self._analyze_subdomain(subdomain, base_domain)
        else:
            self.log("info", "No additional subdomains discovered")

        self.log("info", "Subdomain discovery complete")

    def _detect_wildcard_dns(self, base_domain: str) -> bool:
        """Check if the domain has wildcard DNS by resolving random subdomains."""
        random_labels = [
            "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
            for _ in range(3)
        ]
        resolved = 0
        for label in random_labels:
            try:
                socket.gethostbyname(f"{label}.{base_domain}")
                resolved += 1
            except socket.gaierror:
                pass
        # If 2+ random subdomains resolve, it's wildcard DNS
        return resolved >= 2

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
