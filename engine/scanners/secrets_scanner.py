"""
HackerPA Engine - Secrets Scanner

Scrapes the frontend HTML and JavaScript bundles looking for hardcoded
API keys, tokens, passwords, database connection strings, and other secrets.
"""

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from engine.scanners.base_scanner import BaseScanner
from engine import config


class SecretsScanner(BaseScanner):
    scanner_name = "secrets_scanner"

    def run(self) -> None:
        self.log("info", f"Scanning frontend for exposed secrets: {self.base_url}")

        # Fetch main page
        response = self.make_request(self.base_url)
        if response is None:
            self.log("error", f"Could not reach {self.base_url}")
            return

        # Scan the main HTML
        self._scan_content(response.text, self.base_url)

        # Find and scan linked JavaScript files
        js_urls = self._extract_js_urls(response.text)
        self.log("info", f"Found {len(js_urls)} JavaScript files to scan")

        for js_url in js_urls:
            full_url = urljoin(self.base_url, js_url)
            js_response = self.make_request(full_url)
            if js_response and js_response.status_code == 200:
                self._scan_content(js_response.text, full_url)

        self.log("info", "Secrets scan complete")

    def _extract_js_urls(self, html: str) -> list[str]:
        """Extract JavaScript file URLs from HTML."""
        urls = []
        try:
            soup = BeautifulSoup(html, "lxml")
            for script in soup.find_all("script", src=True):
                src = script["src"]
                if src and not src.startswith("data:"):
                    urls.append(src)
        except Exception as e:
            self.log("warning", f"Error parsing HTML for scripts: {e}")
        return urls

    def _scan_content(self, content: str, source_url: str) -> None:
        """Scan text content for secret patterns."""
        for pattern in config.SECRET_PATTERNS:
            try:
                matches = re.finditer(pattern, content)
                for match in matches:
                    secret_value = match.group(0)
                    # Mask the secret for evidence (show first/last 4 chars)
                    masked = self._mask_secret(secret_value)

                    # Determine severity based on pattern type
                    severity = self._classify_severity(pattern, secret_value)

                    # Get surrounding context (50 chars each side)
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].replace("\n", " ").strip()

                    self.add_finding(
                        severity=severity,
                        title=self._classify_title(pattern),
                        description=f"Um secret/token foi encontrado exposto no codigo fonte acessivel publicamente. "
                                    f"Atacantes podem usar isso para acessar servicos, bancos de dados ou APIs.",
                        evidence={
                            "url": source_url,
                            "payload": masked,
                            "response_snippet": self._mask_context(context),
                        },
                        remediation=self.get_remediation_with_code("secrets",
                            "1. Revogue o secret/token imediatamente.\n"
                            "2. Mova para variaveis de ambiente (process.env / .env).\n"
                            "3. Nunca inclua secrets no codigo frontend.\n"
                            "4. Use um gerenciador de secrets (Vault, AWS Secrets Manager, etc)."),
                        owasp_category="A02:2021 - Cryptographic Failures",
                        cvss_score=8.5 if severity == "critical" else 6.5,
                        affected_url=source_url,
                    )
            except re.error:
                continue

    def _mask_secret(self, secret: str) -> str:
        """Mask a secret value, showing only first and last 4 characters."""
        if len(secret) <= 8:
            return secret[:2] + "*" * (len(secret) - 2)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    def _mask_context(self, context: str) -> str:
        """Mask secrets in context snippet."""
        for pattern in config.SECRET_PATTERNS:
            try:
                context = re.sub(pattern, lambda m: self._mask_secret(m.group(0)), context)
            except re.error:
                continue
        return context

    def _classify_severity(self, pattern: str, value: str) -> str:
        """Classify severity based on the type of secret found."""
        critical_indicators = [
            "PRIVATE KEY", "password", "passwd", "db_password",
            "database_url", "mongodb", "postgres", "mysql", "redis",
            "aws_secret", "sk_live", "sk-live",
        ]
        high_indicators = [
            "api_key", "api_secret", "access_token", "auth_token",
            "secret_key", "ghp_", "github_pat", "xox", "sk_test", "sk-test",
        ]

        pattern_lower = pattern.lower()
        value_lower = value.lower()

        for indicator in critical_indicators:
            if indicator in pattern_lower or indicator in value_lower:
                return "critical"

        for indicator in high_indicators:
            if indicator in pattern_lower or indicator in value_lower:
                return "high"

        # JWT tokens
        if value.startswith("eyJ"):
            return "high"

        return "medium"

    def _classify_title(self, pattern: str) -> str:
        """Generate a human-readable title based on the pattern."""
        pattern_lower = pattern.lower()

        if "private.key" in pattern_lower or "PRIVATE KEY" in pattern:
            return "Chave privada exposta no frontend"
        if "password" in pattern_lower or "passwd" in pattern_lower:
            return "Senha hardcoded encontrada no codigo"
        if "mongodb" in pattern_lower or "postgres" in pattern_lower or "mysql" in pattern_lower:
            return "String de conexao de banco de dados exposta"
        if "aws" in pattern_lower:
            return "Credencial AWS exposta"
        if "stripe" in pattern_lower or "sk_live" in pattern_lower or "sk-live" in pattern_lower:
            return "Chave Stripe exposta"
        if "github" in pattern_lower or "ghp_" in pattern_lower:
            return "Token GitHub exposto"
        if "slack" in pattern_lower or "xox" in pattern_lower:
            return "Token Slack exposto"
        if "firebase" in pattern_lower or "AIza" in pattern:
            return "Chave Google/Firebase exposta"
        if "jwt" in pattern_lower or "eyJ" in pattern:
            return "JWT Token exposto no frontend"
        if "api.key" in pattern_lower or "api_key" in pattern_lower:
            return "API Key exposta no codigo fonte"
        if "api.secret" in pattern_lower or "secret" in pattern_lower:
            return "API Secret exposto no codigo fonte"
        if "token" in pattern_lower:
            return "Token de acesso exposto no frontend"

        return "Secret/credencial exposta no codigo fonte"
