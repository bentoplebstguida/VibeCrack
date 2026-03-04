"""
VibeCrack Engine - Subdomain Discovery Scanner

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
                title=f"Wildcard DNS detected: *.{base_domain}",
                description=(
                    f"The domain {base_domain} uses wildcard DNS, meaning any subdomain "
                    f"(e.g., xyz123.{base_domain}) resolves to an IP. This is common on "
                    f"platforms like Cloud Run, Vercel, Netlify, etc. "
                    f"Subdomain enumeration via DNS is not effective in this case."
                ),
                evidence={"url": f"*.{base_domain}"},
                remediation="Wildcard DNS is normal for cloud platforms. No action required.",
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
                    f"Development/test environment exposed: {subdomain}"
                    if is_risky
                    else f"Active subdomain discovered: {subdomain}"
                )
                description = (
                    f"The subdomain '{subdomain}' is publicly accessible. "
                    f"Dev/staging environments often have reduced security, "
                    f"debug enabled, and may expose real data."
                    if is_risky
                    else f"The subdomain '{subdomain}' is active and responding."
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
                        "1. Protect dev/staging environments with authentication (HTTP Basic Auth or VPN).\n"
                        "2. Do not use real data in test environments.\n"
                        "3. Keep debug disabled even in staging.\n"
                        "4. Use private DNS or VPN to access internal environments."
                        if is_risky
                        else "Verify whether this subdomain needs to be public and whether it is adequately protected."
                    ),
                    owasp_category="A05:2021 - Security Misconfiguration",
                    cvss_score=7.0 if is_risky else 2.0,
                    affected_url=url,
                )
                break  # Found on one scheme, no need to check the other
