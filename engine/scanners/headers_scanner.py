"""
HackerPA Engine - Security Headers Scanner

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
                title="Site inacessivel",
                description=f"Nao foi possivel acessar {self.base_url}. Verifique se o dominio esta correto e acessivel.",
                remediation="Verifique se o dominio esta correto, o DNS esta configurado, e o servidor esta respondendo.",
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
                        title=f"Header de seguranca ausente: {header_name}",
                        description=f"{header_config['description']}. Este header nao foi encontrado na resposta do servidor.",
                        evidence={"url": self.base_url, "response_snippet": f"Header '{header_name}' nao presente na resposta"},
                        remediation=self.get_remediation_with_code("headers",
                            f"Adicione o header '{header_name}' nas respostas do servidor. Consulte: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header_name}"),
                        owasp_category="A05:2021 - Security Misconfiguration",
                        cvss_score=6.5 if header_config["severity"] == "high" else 4.0,
                        affected_url=self.base_url,
                    )
                else:
                    missing_optional.append(header_name)
                    self.add_finding(
                        severity="info",
                        title=f"Header opcional ausente: {header_name}",
                        description=f"{header_config['description']}. Recomendado mas nao obrigatorio.",
                        remediation=self.get_remediation_with_code("headers",
                            f"Considere adicionar o header '{header_name}' para maior seguranca."),
                        owasp_category="A05:2021 - Security Misconfiguration",
                        affected_url=self.base_url,
                    )
            else:
                # Check expected value if defined
                expected = header_config.get("expected")
                if expected and value.lower() != expected.lower():
                    self.add_finding(
                        severity="low",
                        title=f"Header com valor inesperado: {header_name}",
                        description=f"Esperado '{expected}', encontrado '{value}'.",
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
                title="Header 'Server' expoe informacoes do servidor",
                description=f"O header 'Server' revela: '{server_header}'. Isso ajuda atacantes a identificar o software usado.",
                evidence={"url": self.base_url, "response_snippet": f"Server: {server_header}"},
                remediation=self.get_remediation_with_code("headers",
                    "Remova ou ofusque o header 'Server' na configuracao do seu web server."),
                owasp_category="A05:2021 - Security Misconfiguration",
                cvss_score=2.0,
                affected_url=self.base_url,
            )

        x_powered = headers.get("X-Powered-By")
        if x_powered:
            self.add_finding(
                severity="low",
                title="Header 'X-Powered-By' expoe tecnologia",
                description=f"O header 'X-Powered-By' revela: '{x_powered}'. Isso ajuda atacantes a identificar frameworks e versoes.",
                evidence={"url": self.base_url, "response_snippet": f"X-Powered-By: {x_powered}"},
                remediation=self.get_remediation_with_code("headers",
                    "Remova o header 'X-Powered-By'. No Express.js use app.disable('x-powered-by')."),
                owasp_category="A05:2021 - Security Misconfiguration",
                cvss_score=2.0,
                affected_url=self.base_url,
            )

        self.log("info", f"Headers scan complete. {len(missing_required)} required missing, {len(missing_optional)} optional missing.")
