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

    # Patterns that indicate webpack/vite chunk references inside JS bundles
    _CHUNK_PATTERNS: list[re.Pattern] = [
        # Webpack: "/static/js/chunk-" or "static/js/" followed by chunk id
        re.compile(r'["\'](/static/js/[^"\']+\.js)["\']'),
        # Next.js: "/_next/static/chunks/"
        re.compile(r'["\'](/_next/static/chunks/[^"\']+\.js)["\']'),
        # Vite: "/assets/" chunk references
        re.compile(r'["\'](/assets/[^"\']+\.js)["\']'),
        # Generic chunk patterns with hash
        re.compile(r'["\']([^"\']*chunk[^"\']*\.js)["\']'),
    ]

    def run(self) -> None:
        self.log("info", f"Scanning frontend for exposed secrets: {self.base_url}")

        # Track all JS URLs we've already scanned to avoid duplicates
        scanned_js: set[str] = set()

        # Fetch main page
        response = self.make_request(self.base_url)
        if response is None:
            self.log("error", f"Could not reach {self.base_url}")
            return

        # Scan the main HTML
        self._scan_content(response.text, self.base_url)

        # Scan inline <script> tag contents from the HTML page
        self._scan_inline_scripts(response.text, self.base_url)

        # Find and scan linked JavaScript files
        js_urls = self._extract_js_urls(response.text)
        self.log("info", f"Found {len(js_urls)} JavaScript files to scan")

        # Also include JS files discovered by the crawler
        crawl_js_files = self.crawl_data.get("jsFiles", [])
        if crawl_js_files:
            self.log("info", f"Adding {len(crawl_js_files)} JS files from crawler data")
            for crawl_js in crawl_js_files:
                if crawl_js not in js_urls:
                    js_urls.append(crawl_js)

        # Collect chunk URLs discovered inside JS bundles for a second pass
        discovered_chunks: list[str] = []

        for js_url in js_urls:
            full_url = urljoin(self.base_url, js_url)
            if full_url in scanned_js:
                continue
            scanned_js.add(full_url)

            js_response = self.make_request(full_url)
            if js_response and js_response.status_code == 200:
                self._scan_content(js_response.text, full_url)

                # Discover webpack/vite chunk references inside this JS file
                chunks = self._discover_chunks(js_response.text, full_url)
                discovered_chunks.extend(chunks)

                # Try fetching the source map for this JS file
                self._scan_source_map(full_url)

        # Second pass: scan discovered chunk files
        if discovered_chunks:
            self.log("info", f"Discovered {len(discovered_chunks)} JS chunk file(s) to scan")
        for chunk_url in discovered_chunks:
            if chunk_url in scanned_js:
                continue
            scanned_js.add(chunk_url)

            try:
                chunk_response = self.make_request(chunk_url)
                if chunk_response and chunk_response.status_code == 200:
                    self._scan_content(chunk_response.text, chunk_url)
                    # Also check source maps for chunk files
                    self._scan_source_map(chunk_url)
            except Exception as exc:
                self.log("warning", f"Error scanning chunk {chunk_url}: {exc}")

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

    def _scan_inline_scripts(self, html: str, page_url: str) -> None:
        """Extract and scan the contents of inline <script> tags."""
        try:
            soup = BeautifulSoup(html, "lxml")
            inline_scripts = soup.find_all("script", src=False)
            count = 0
            for script in inline_scripts:
                script_text = script.get_text(strip=True)
                if script_text and len(script_text) > 10:
                    self._scan_content(script_text, f"{page_url} (inline script)")
                    count += 1
            if count:
                self.log("info", f"Scanned {count} inline script(s) from {page_url}")
        except Exception as exc:
            self.log("warning", f"Error extracting inline scripts: {exc}")

    def _discover_chunks(self, js_content: str, source_url: str) -> list[str]:
        """Look for webpack/vite chunk file references inside a JS bundle
        and return their full URLs."""
        chunks: list[str] = []
        seen: set[str] = set()

        for pattern in self._CHUNK_PATTERNS:
            try:
                for match in pattern.finditer(js_content):
                    chunk_path = match.group(1)
                    full_url = urljoin(self.base_url, chunk_path)
                    if full_url not in seen:
                        seen.add(full_url)
                        chunks.append(full_url)
            except Exception:
                continue

        if chunks:
            self.log("info", f"Found {len(chunks)} chunk reference(s) in {source_url}")
        return chunks

    def _scan_source_map(self, js_url: str) -> None:
        """Try fetching ``{js_url}.map`` and scan it for secrets.

        Source maps often contain the original source code which may
        include hardcoded secrets that were minified away in the bundle.
        """
        map_url = f"{js_url}.map"
        try:
            map_response = self.make_request(map_url)
            if map_response is None:
                return

            # Source maps return 200 with JSON content when they exist.
            # Many servers return 404 or non-JSON; skip those.
            if map_response.status_code != 200:
                return

            content_type = map_response.headers.get("Content-Type", "")
            # Accept JSON or octet-stream (some servers misconfigure MIME)
            if "json" not in content_type and "javascript" not in content_type and "octet" not in content_type and "text" not in content_type:
                return

            # Source map is valid - this is already a finding by itself
            self.log("info", f"Source map found: {map_url}")

            # Scan the raw source map text for secrets
            self._scan_content(map_response.text, map_url)

        except Exception as exc:
            self.log("warning", f"Error checking source map {map_url}: {exc}")

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
