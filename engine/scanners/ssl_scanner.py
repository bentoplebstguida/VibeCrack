"""
HackerPA Engine - SSL/TLS Scanner

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
                    title="HTTP nao redireciona para HTTPS",
                    description="O site aceita conexoes HTTP sem redirecionar para HTTPS. Dados podem ser interceptados em transito.",
                    evidence={"url": http_url, "response_snippet": f"Status: {response.status_code}, Location: {location}"},
                    remediation="Configure um redirect 301 de HTTP para HTTPS no seu web server ou load balancer.",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    cvss_score=7.5,
                    affected_url=http_url,
                )
        elif response.status_code == 200:
            self.add_finding(
                severity="high",
                title="Site acessivel via HTTP sem redirect",
                description="O site responde via HTTP (porta 80) sem redirecionar para HTTPS. Dados trafegam sem encriptacao.",
                evidence={"url": http_url, "response_snippet": f"Status: {response.status_code} (sem redirect)"},
                remediation="Configure um redirect 301 de HTTP para HTTPS. Todo trafego deve ser encriptado.",
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
                            title="Certificado SSL nao encontrado",
                            description="O servidor nao apresentou um certificado SSL valido.",
                            remediation="Instale um certificado SSL valido. Use Let's Encrypt para certificados gratuitos.",
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
                                title="Certificado SSL expirado",
                                description=f"O certificado expirou ha {abs(days_left)} dias ({not_after}). Navegadores mostram erro de seguranca.",
                                evidence={"url": self.base_url, "response_snippet": f"Expiry: {not_after}, Days: {days_left}"},
                                remediation="Renove o certificado SSL imediatamente. Use Let's Encrypt com auto-renovacao.",
                                owasp_category="A02:2021 - Cryptographic Failures",
                                cvss_score=9.0,
                                affected_url=self.base_url,
                            )
                        elif days_left < 30:
                            self.add_finding(
                                severity="medium",
                                title=f"Certificado SSL expira em {days_left} dias",
                                description=f"O certificado expira em {not_after}. Renove antes que expire para evitar interrupcoes.",
                                evidence={"url": self.base_url, "response_snippet": f"Expiry: {not_after}, Days left: {days_left}"},
                                remediation="Renove o certificado SSL. Configure auto-renovacao com Let's Encrypt ou seu provedor de SSL.",
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
                title="Certificado SSL invalido",
                description=f"O certificado nao passou na verificacao: {e}. Navegadores vao bloquear o acesso.",
                evidence={"url": self.base_url, "response_snippet": str(e)},
                remediation="Corrija o certificado SSL. Causas comuns: certificado auto-assinado, CN incorreto, cadeia incompleta.",
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
                            title=f"Protocolo inseguro suportado: {proto_name}",
                            description=f"O servidor aceita conexoes {proto_name}, que tem vulnerabilidades conhecidas (POODLE, BEAST).",
                            evidence={"url": self.base_url, "response_snippet": f"{proto_name} connection successful"},
                            remediation=f"Desabilite {proto_name} no servidor. Use apenas TLS 1.2 e TLS 1.3.",
                            owasp_category="A02:2021 - Cryptographic Failures",
                            cvss_score=7.0 if severity == "critical" else 5.0,
                            affected_url=self.base_url,
                        )
            except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
                self.log("info", f"{proto_name} not supported (good)")
