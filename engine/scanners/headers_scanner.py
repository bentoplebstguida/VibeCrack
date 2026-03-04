"""
VibeCrack Engine - Security Headers Scanner

Checks for the presence and correct configuration of HTTP security headers
(HSTS, CSP, X-Frame-Options, etc.).
"""

from engine.scanners.base_scanner import BaseScanner
from engine import config


class HeadersScanner(BaseScanner):
    scanner_name = "headers_scanner"

    def run(self) -> None:
        self.log("info", f"Checking security headers for {self.base_url}")

        response = self.make_request(self.base_url)
        if response is None:
            self.log("error", f"Could not reach {self.base_url}")
            self.add_finding(
                severity="high",
                title="Site unreachable",
                description=f"Could not access {self.base_url}. Verify the domain is correct and accessible.",
                remediation="Verify the domain is correct, DNS is configured, and the server is responding.",
                owasp_category="A05:2021 - Security Misconfiguration",
                affected_url=self.base_url,
            )
            return

        headers = response.headers
        self.log("info", f"Response status: {response.status_code}, checking {len(config.SECURITY_HEADERS)} headers")

        missing_required = []
        missing_optional = []

        for header_name, header_config in config.SECURITY_HEADERS.items():
            value = headers.get(header_name)

            if value is None:
                if header_config["required"]:
                    missing_required.append(header_name)
                    self.add_finding(
                        severity=header_config["severity"],
                        title=f"Missing security header: {header_name}",
                        description=f"{header_config['description']}. This header was not found in the server response.",
                        evidence={"url": self.base_url, "response_snippet": f"Header '{header_name}' not present in response"},
                        remediation=self.get_remediation_with_code("headers",
                            f"Add the '{header_name}' header to server responses. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header_name}"),
                        owasp_category="A05:2021 - Security Misconfiguration",
                        cvss_score=6.5 if header_config["severity"] == "high" else 4.0,
                        affected_url=self.base_url,
                    )
                else:
                    missing_optional.append(header_name)
                    self.add_finding(
                        severity="info",
                        title=f"Optional header missing: {header_name}",
                        description=f"{header_config['description']}. Recommended but not required.",
                        remediation=self.get_remediation_with_code("headers",
                            f"Consider adding the '{header_name}' header for better security."),
                        owasp_category="A05:2021 - Security Misconfiguration",
                        affected_url=self.base_url,
                    )
            else:
                # Check expected value if defined
                expected = header_config.get("expected")
                if expected and value.lower() != expected.lower():
                    self.add_finding(
                        severity="low",
                        title=f"Header with unexpected value: {header_name}",
                        description=f"Expected '{expected}', found '{value}'.",
                        evidence={"url": self.base_url, "payload": f"{header_name}: {value}", "response_snippet": f"Expected: {expected}"},
                        remediation=self.get_remediation_with_code("headers",
                            f"Configure o header '{header_name}' com o valor '{expected}'."),
                        owasp_category="A05:2021 - Security Misconfiguration",
                        cvss_score=2.0,
                        affected_url=self.base_url,
                    )
                else:
                    self.log("info", f"Header OK: {header_name} = {value}")

        # Check for information disclosure headers
        server_header = headers.get("Server")
        if server_header:
            self.add_finding(
                severity="low",
                title="'Server' header exposes server information",
                description=f"The 'Server' header reveals: '{server_header}'. This helps attackers identify the software in use.",
                evidence={"url": self.base_url, "response_snippet": f"Server: {server_header}"},
                remediation=self.get_remediation_with_code("headers",
                    "Remove or obfuscate the 'Server' header in your web server configuration."),
                owasp_category="A05:2021 - Security Misconfiguration",
                cvss_score=2.0,
                affected_url=self.base_url,
            )

        x_powered = headers.get("X-Powered-By")
        if x_powered:
            self.add_finding(
                severity="low",
                title="'X-Powered-By' header exposes technology",
                description=f"The 'X-Powered-By' header reveals: '{x_powered}'. This helps attackers identify frameworks and versions.",
                evidence={"url": self.base_url, "response_snippet": f"X-Powered-By: {x_powered}"},
                remediation=self.get_remediation_with_code("headers",
                    "Remove the 'X-Powered-By' header. In Express.js use app.disable('x-powered-by')."),
                owasp_category="A05:2021 - Security Misconfiguration",
                cvss_score=2.0,
                affected_url=self.base_url,
            )

        self.log("info", f"Headers scan complete. {len(missing_required)} required missing, {len(missing_optional)} optional missing.")
