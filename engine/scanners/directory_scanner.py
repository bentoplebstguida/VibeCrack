"""
VibeCrack Engine - Directory & Sensitive Files Scanner

Checks for exposed sensitive files and directories like .env, .git,
admin panels, backup files, config files, and other paths that should
not be publicly accessible.
"""

from urllib.parse import urljoin

from engine.scanners.base_scanner import BaseScanner
from engine import config


# Severity classification for different types of exposed paths
PATH_SEVERITY = {
    "/.env": ("critical", "Exposed .env file with environment variables", "Contains passwords, API keys, and sensitive server configurations."),
    "/.env.local": ("critical", "Exposed .env.local file", "Contains local environment variables, often with production secrets."),
    "/.env.production": ("critical", "Exposed .env.production file", "Contains production environment variables with real secrets."),
    "/.git/config": ("critical", "Exposed Git repository", "Attackers can download the entire source code, including commit history with possible secrets."),
    "/.git/HEAD": ("critical", "Exposed Git repository (HEAD)", "Confirms the .git directory is publicly accessible."),
    "/dump.sql": ("critical", "Exposed database dump", "Contains all database data including possible passwords and personal data."),
    "/database.sql": ("critical", "Exposed SQL database file", "Contains database structure and possibly data."),
    "/phpinfo.php": ("high", "Exposed phpinfo()", "Reveals full PHP configuration, server paths, and software versions."),
    "/info.php": ("high", "Exposed PHP info file", "May reveal sensitive server configurations."),
    "/wp-admin/": ("medium", "Accessible WordPress admin panel", "WordPress admin panel is publicly accessible."),
    "/admin/": ("medium", "Accessible admin panel", "Admin area is publicly accessible. Verify it requires authentication."),
    "/administrator/": ("medium", "Accessible administrator panel", "Admin area is publicly accessible."),
    "/swagger.json": ("medium", "Exposed Swagger/OpenAPI documentation", "Reveals all API endpoints, parameters, and data structures."),
    "/openapi.json": ("medium", "Exposed OpenAPI documentation", "Reveals all API endpoints publicly."),
    "/api/docs": ("medium", "Exposed API documentation", "Interactive API documentation accessible without authentication."),
    "/server-status": ("medium", "Exposed Apache server-status", "Reveals information about active connections and server configuration."),
    "/server-info": ("medium", "Exposed Apache server-info", "Reveals detailed Apache server configuration."),
    "/composer.json": ("medium", "Exposed composer.json", "Reveals PHP dependencies and their versions, useful for finding CVEs."),
    "/package.json": ("low", "Exposed package.json", "Reveals Node.js dependencies and their versions."),
    "/Dockerfile": ("medium", "Exposed Dockerfile", "Reveals container configuration and possibly build secrets."),
    "/docker-compose.yml": ("medium", "Exposed docker-compose.yml", "Reveals service architecture and possibly credentials."),
    "/.dockerenv": ("medium", "Docker container detected", "The server is running in a Docker container."),
    "/backup/": ("high", "Accessible backup directory", "Backups may contain sensitive data, source code, and configurations."),
    "/backups/": ("high", "Accessible backups directory", "Backups may contain sensitive data and source code."),
    "/.htaccess": ("medium", "Accessible .htaccess file", "Reveals rewrite rules, directory protections, and Apache configuration."),
    "/web.config": ("medium", "Exposed web.config", "Reveals IIS/ASP.NET configuration, possibly connection strings."),
    "/robots.txt": ("info", "robots.txt found", "May reveal sensitive paths the site tries to hide from search engines."),
    "/sitemap.xml": ("info", "sitemap.xml found", "Maps all pages on the site."),
    "/.well-known/security.txt": ("info", "security.txt found", "Good! The site has a published security contact."),
    "/.DS_Store": ("low", "Exposed .DS_Store", "macOS metadata file may reveal filenames in the directory."),
    "/thumbs.db": ("low", "Exposed thumbs.db", "Windows metadata file may reveal filenames."),
    "/.npmrc": ("high", "Exposed .npmrc", "May contain npm registry authentication tokens."),
    "/.gitignore": ("info", "Accessible .gitignore", "Reveals which files the project ignores, indicating the tech stack."),
    "/config.php": ("high", "Exposed config.php", "PHP configuration file often contains database credentials."),
    "/config.yml": ("high", "Exposed config.yml", "YAML configuration file may contain secrets."),
    "/config.json": ("high", "Exposed config.json", "JSON configuration file may contain secrets and API keys."),
    "/test.php": ("medium", "Accessible PHP test file", "Test files should not be in production."),
    "/api/": ("info", "Accessible base API endpoint", "API base responds. Verify it requires authentication."),
    "/console/": ("high", "Accessible debug console", "Debug console (e.g. Werkzeug) is publicly accessible. Allows code execution."),
    "/debug/": ("high", "Accessible debug endpoint", "Debug mode is active in production. May reveal stack traces and internal information."),
    "/trace/": ("medium", "Accessible trace endpoint", "May reveal debug information and stack traces."),
    "/.vscode/": ("low", "Exposed .vscode directory", "VSCode settings may reveal developer extensions and configurations."),
    "/.idea/": ("low", "Exposed .idea directory", "IntelliJ/WebStorm configurations exposed."),
}


class DirectoryScanner(BaseScanner):
    scanner_name = "directory_scanner"

    def run(self) -> None:
        self.log("info", f"Scanning for sensitive files/directories: {self.base_url}")

        found_count = 0

        for path in config.SENSITIVE_PATHS:
            url = urljoin(self.base_url.rstrip("/") + "/", path.lstrip("/"))
            response = self.make_request(url, allow_redirects=False)

            if response is None:
                continue

            # Consider it found if we get a 200 OK
            if response.status_code == 200:
                # Verify it's not a custom 404 page
                if self._is_real_content(response, path):
                    found_count += 1
                    severity_info = PATH_SEVERITY.get(path, ("medium", f"Sensitive path accessible: {path}", "This path should not be publicly accessible."))
                    severity, title, description = severity_info

                    # Get a snippet of the content for evidence
                    snippet = response.text[:500] if response.text else "(empty response)"

                    self.add_finding(
                        severity=severity,
                        title=title,
                        description=description,
                        evidence={
                            "url": url,
                            "response_snippet": snippet[:200],
                        },
                        remediation=self.get_remediation_with_code("directories", self._get_remediation(path)),
                        owasp_category="A01:2021 - Broken Access Control",
                        cvss_score=self._severity_to_cvss(severity),
                        affected_url=url,
                    )
                    self.log("warning", f"FOUND: {path} (status {response.status_code})")
            elif response.status_code == 403:
                # 403 means the path exists but is protected
                self.log("info", f"Protected (403): {path}")
                self.add_finding(
                    severity="info",
                    title=f"Path exists but returns 403: {path}",
                    description=f"The path '{path}' exists on the server but access is blocked (403 Forbidden). This confirms the resource exists.",
                    remediation="Consider returning 404 instead of 403 to avoid confirming the existence of sensitive paths.",
                    owasp_category="A01:2021 - Broken Access Control",
                    affected_url=url,
                )

        self.log("info", f"Directory scan complete. Found {found_count} exposed paths.")

    def _is_real_content(self, response, path: str) -> bool:
        """Try to distinguish real content from custom 404 pages."""
        content = response.text.lower()
        content_length = len(response.text)

        # Very short responses for paths that should have content are suspicious
        if path.endswith((".php", ".json", ".yml", ".xml")) and content_length < 10:
            return False

        # Common 404 page indicators
        not_found_indicators = [
            "page not found",
            "404 not found",
            "404 error",
            "not found",
            "does not exist",
            "pagina nao encontrada",  # Portuguese 404
        ]
        for indicator in not_found_indicators:
            if indicator in content:
                return False

        return True

    def _get_remediation(self, path: str) -> str:
        """Get specific remediation advice based on the path."""
        if ".env" in path:
            return ("1. Remove the .env file from the public directory.\n"
                    "2. Block access to .env files in your web server (e.g. nginx: location ~ /\\.env { deny all; }).\n"
                    "3. Use system environment variables or a secrets manager.\n"
                    "4. Revoke all credentials contained in the file.")
        if ".git" in path:
            return ("1. Remove the .git directory from production deployments.\n"
                    "2. Block access to /.git in your web server.\n"
                    "3. Review commit history for leaked secrets.\n"
                    "4. Configure your deploy pipeline to exclude .git.")
        if "admin" in path.lower():
            return ("1. Protect the admin panel with strong authentication.\n"
                    "2. Restrict access by IP if possible.\n"
                    "3. Use 2FA for administrative access.\n"
                    "4. Consider changing the default admin panel URL.")
        if "backup" in path.lower() or "dump" in path.lower():
            return ("1. Remove backups from the public directory immediately.\n"
                    "2. Store backups in a secure location (private S3, etc).\n"
                    "3. Block access to backup extensions (.sql, .bak, .zip).")
        if "swagger" in path.lower() or "openapi" in path.lower() or "api/docs" in path:
            return ("1. Protect API documentation with authentication.\n"
                    "2. Disable Swagger/OpenAPI in production.\n"
                    "3. Require authorization to access documentation.")
        if "debug" in path.lower() or "console" in path.lower():
            return ("1. Disable debug mode in production IMMEDIATELY.\n"
                    "2. Flask: app.debug = False. Django: DEBUG = False.\n"
                    "3. Express: remove debug middleware.\n"
                    "4. Debug console in production allows remote code execution.")

        return ("1. Block access to this path in your web server.\n"
                "2. Remove unnecessary files from production deployments.\n"
                "3. Use .gitignore and deploy scripts to avoid exposing sensitive files.")

    def _severity_to_cvss(self, severity: str) -> float:
        """Map severity to approximate CVSS score."""
        return {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 3.0,
            "info": 0.0,
        }.get(severity, 5.0)
