"""
VibeCrack Engine - SSL/TLS Scanner

Checks SSL certificate validity, expiration, protocol versions,
and common TLS misconfigurations.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from engine.scanners.base_scanner import BaseScanner


class SSLScanner(BaseScanner):
    scanner_name = "ssl_scanner"

    def run(self) -> None:
        self.log("info", f"Checking SSL/TLS for {self.base_url}")

        parsed = urlparse(self.base_url)
        hostname = parsed.hostname or self.domain
        port = parsed.port or 443

        # Check if site uses HTTPS
        if parsed.scheme == "http":
            self._check_https_redirect()

        # Get certificate info
        self._check_certificate(hostname, port)

        # Check TLS versions
        self._check_tls_versions(hostname, port)

        self.log("info", "SSL/TLS scan complete")

    def _check_https_redirect(self) -> None:
        """Check if HTTP redirects to HTTPS."""
        http_url = self.base_url.replace("https://", "http://")
        response = self.make_request(http_url, allow_redirects=False)

        if response is None:
            return

        if response.status_code in (301, 302, 307, 308):
            location = response.headers.get("Location", "")
            if location.startswith("https://"):
                self.log("info", "HTTP correctly redirects to HTTPS")
            else:
                self.add_finding(
                    severity="high",
                    title="HTTP does not redirect to HTTPS",
                    description="The site accepts HTTP connections without redirecting to HTTPS. Data can be intercepted in transit.",
                    evidence={"url": http_url, "response_snippet": f"Status: {response.status_code}, Location: {location}"},
                    remediation=self.get_remediation_with_code("ssl",
                    "Configure a 301 redirect from HTTP to HTTPS on your web server or load balancer."),
                    owasp_category="A02:2021 - Cryptographic Failures",
                    cvss_score=7.5,
                    affected_url=http_url,
                )
        elif response.status_code == 200:
            self.add_finding(
                severity="high",
                title="Site accessible via HTTP without redirect",
                description="The site responds via HTTP (port 80) without redirecting to HTTPS. Data travels without encryption.",
                evidence={"url": http_url, "response_snippet": f"Status: {response.status_code} (no redirect)"},
                remediation=self.get_remediation_with_code("ssl",
                    "Configure a 301 redirect from HTTP to HTTPS. All traffic should be encrypted."),
                owasp_category="A02:2021 - Cryptographic Failures",
                cvss_score=7.5,
                affected_url=http_url,
            )

    def _check_certificate(self, hostname: str, port: int) -> None:
        """Check certificate validity and expiration."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    if not cert:
                        self.add_finding(
                            severity="critical",
                            title="SSL certificate not found",
                            description="The server did not present a valid SSL certificate.",
                            remediation=self.get_remediation_with_code("ssl",
                            "Install a valid SSL certificate. Use Let's Encrypt for free certificates."),
                            owasp_category="A02:2021 - Cryptographic Failures",
                            cvss_score=9.0,
                            affected_url=self.base_url,
                        )
                        return

                    # Check expiration
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry = expiry.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_left = (expiry - now).days

                        if days_left < 0:
                            self.add_finding(
                                severity="critical",
                                title="SSL certificate expired",
                                description=f"The certificate expired {abs(days_left)} days ago ({not_after}). Browsers show security error.",
                                evidence={"url": self.base_url, "response_snippet": f"Expiry: {not_after}, Days: {days_left}"},
                                remediation=self.get_remediation_with_code("ssl",
                                    "Renew the SSL certificate immediately. Use Let's Encrypt with auto-renewal."),
                                owasp_category="A02:2021 - Cryptographic Failures",
                                cvss_score=9.0,
                                affected_url=self.base_url,
                            )
                        elif days_left < 30:
                            self.add_finding(
                                severity="medium",
                                title=f"SSL certificate expires in {days_left} days",
                                description=f"The certificate expires on {not_after}. Renew before it expires to avoid disruptions.",
                                evidence={"url": self.base_url, "response_snippet": f"Expiry: {not_after}, Days left: {days_left}"},
                                remediation=self.get_remediation_with_code("ssl",
                                    "Renew the SSL certificate. Configure auto-renewal with Let's Encrypt or your SSL provider."),
                                owasp_category="A02:2021 - Cryptographic Failures",
                                cvss_score=4.0,
                                affected_url=self.base_url,
                            )
                        else:
                            self.log("info", f"Certificate valid for {days_left} more days")

                    # Check subject
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "")
                    self.log("info", f"Certificate CN: {cn}")

                    # Check issuer
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    issuer_cn = issuer.get("commonName", "")
                    issuer_org = issuer.get("organizationName", "")
                    self.log("info", f"Issuer: {issuer_org} ({issuer_cn})")

        except ssl.SSLCertVerificationError as e:
            self.add_finding(
                severity="critical",
                title="Invalid SSL certificate",
                description=f"The certificate failed verification: {e}. Browsers will block access.",
                evidence={"url": self.base_url, "response_snippet": str(e)},
                remediation=self.get_remediation_with_code("ssl",
                    "Fix the SSL certificate. Common causes: self-signed certificate, incorrect CN, incomplete chain."),
                owasp_category="A02:2021 - Cryptographic Failures",
                cvss_score=9.0,
                affected_url=self.base_url,
            )
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            self.log("warning", f"Could not connect to {hostname}:{port} - {e}")

    def _check_tls_versions(self, hostname: str, port: int) -> None:
        """Check if old/insecure TLS versions are supported."""
        old_protocols = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1, "critical"),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "high"),
        ]

        for proto_name, proto_version, severity in old_protocols:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = proto_version
                context.maximum_version = proto_version

                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        self.add_finding(
                            severity=severity,
                            title=f"Insecure protocol supported: {proto_name}",
                            description=f"The server accepts {proto_name} connections, which have known vulnerabilities (POODLE, BEAST).",
                            evidence={"url": self.base_url, "response_snippet": f"{proto_name} connection successful"},
                            remediation=self.get_remediation_with_code("ssl",
                                f"Disable {proto_name} on the server. Use only TLS 1.2 and TLS 1.3."),
                            owasp_category="A02:2021 - Cryptographic Failures",
                            cvss_score=7.0 if severity == "critical" else 5.0,
                            affected_url=self.base_url,
                        )
            except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
                self.log("info", f"{proto_name} not supported (good)")
