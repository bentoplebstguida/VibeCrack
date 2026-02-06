"""
HackerPA Engine - Base Scanner

Abstract base class that every scanner module must inherit from.
Provides common helpers for logging, adding findings, and making
HTTP requests.
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

import requests

from engine import config
from engine.orchestrator import firebase_client

logger = logging.getLogger(__name__)


class CircuitBreaker:
    """Safe Mode: Monitors target server health and stops scanning if
    the server becomes slow or unstable to prevent accidental DoS.

    Tracks response times and error rates. If thresholds are exceeded,
    the circuit 'opens' and requests are paused or stopped.
    """

    def __init__(
        self,
        max_response_time: float = 10.0,
        error_threshold: int = 5,
        cooldown_seconds: float = 30.0,
        window_size: int = 10,
    ):
        self.max_response_time = max_response_time
        self.error_threshold = error_threshold
        self.cooldown_seconds = cooldown_seconds
        self.window_size = window_size

        self._response_times: list[float] = []
        self._error_count: int = 0
        self._is_open: bool = False
        self._opened_at: float = 0

    @property
    def is_open(self) -> bool:
        """Check if circuit is open (target seems unhealthy)."""
        if self._is_open:
            # Check if cooldown has passed
            if time.time() - self._opened_at > self.cooldown_seconds:
                self._is_open = False
                self._error_count = 0
                self._response_times.clear()
                logger.info("Circuit breaker: CLOSED (cooldown passed)")
                return False
            return True
        return False

    def record_success(self, response_time: float) -> None:
        """Record a successful request and its response time."""
        self._response_times.append(response_time)
        if len(self._response_times) > self.window_size:
            self._response_times.pop(0)

        # Check if avg response time is too high (server slowing down)
        if len(self._response_times) >= 3:
            avg_time = sum(self._response_times) / len(self._response_times)
            if avg_time > self.max_response_time:
                self._trip(f"Average response time too high: {avg_time:.1f}s")

    def record_error(self) -> None:
        """Record a failed request."""
        self._error_count += 1
        if self._error_count >= self.error_threshold:
            self._trip(f"Error threshold reached: {self._error_count} errors")

    def _trip(self, reason: str) -> None:
        """Open the circuit breaker."""
        self._is_open = True
        self._opened_at = time.time()
        logger.warning("Circuit breaker: OPEN - %s. Pausing for %.0fs.", reason, self.cooldown_seconds)


class BaseScanner(ABC):
    """Abstract base scanner.

    Parameters
    ----------
    scan_id : str
        The Firestore document ID for the current scan.
    project_id : str
        The project this scan belongs to.
    domain : str
        The target domain (e.g. ``"example.com"``).
    """

    scanner_name: str = "base"

    def __init__(self, scan_id: str, project_id: str, domain: str) -> None:
        self.scan_id = scan_id
        self.project_id = project_id
        self.domain = domain

        # Ensure the domain has a scheme for making requests
        if domain and not domain.startswith(("http://", "https://")):
            self.base_url = f"https://{domain}"
        else:
            self.base_url = domain

        self._session = requests.Session()
        self._session.headers.update({"User-Agent": config.USER_AGENT})

        # Circuit Breaker for Safe Mode (prevents accidental DoS)
        self._circuit_breaker = CircuitBreaker()

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def run(self) -> None:
        """Execute the scanner logic.

        Subclasses must implement this method.  Use ``self.log()``,
        ``self.add_finding()``, and ``self.make_request()`` as needed.
        """
        ...

    # ------------------------------------------------------------------
    # Logging helper
    # ------------------------------------------------------------------

    def log(
        self,
        level: str,
        message: str,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Write a log entry to Firestore and to the local Python logger.

        Parameters
        ----------
        level : str
            One of ``"debug"``, ``"info"``, ``"warning"``, ``"error"``.
        message : str
            Human-readable log message.
        details : dict, optional
            Arbitrary structured data to attach.
        """
        # Local logger
        py_level = getattr(logging, level.upper(), logging.INFO)
        logger.log(py_level, "[%s] scan=%s %s", self.scanner_name, self.scan_id, message)

        # Firestore
        try:
            firebase_client.add_scan_log(
                self.scan_id,
                level=level,
                message=message,
                details=details,
                scanner=self.scanner_name,
            )
        except Exception:
            logger.exception("Failed to write scan log to Firestore")

    # ------------------------------------------------------------------
    # Finding helper
    # ------------------------------------------------------------------

    def add_finding(
        self,
        *,
        severity: str,
        title: str,
        description: str,
        evidence: str = "",
        remediation: str = "",
        owasp_category: str = "",
        cvss_score: float = 0.0,
        affected_url: str = "",
    ) -> str:
        """Record a vulnerability finding in Firestore.

        Parameters
        ----------
        severity : str
            ``"critical"``, ``"high"``, ``"medium"``, ``"low"``, or ``"info"``.
        title : str
            Short human-readable title.
        description : str
            Detailed description of the vulnerability.
        evidence : str
            Proof / snippet that demonstrates the issue.
        remediation : str
            Recommended fix.
        owasp_category : str
            e.g. ``"A01:2021-Broken Access Control"``.
        cvss_score : float
            CVSS v3 base score (0.0 -- 10.0).
        affected_url : str
            The specific URL where the issue was found.

        Returns
        -------
        str
            The Firestore document ID of the new finding.
        """
        self.log("info", f"Finding: [{severity.upper()}] {title}", {
            "affected_url": affected_url,
        })

        try:
            return firebase_client.add_finding(
                self.scan_id,
                severity=severity,
                title=title,
                description=description,
                evidence=evidence,
                remediation=remediation,
                owasp_category=owasp_category,
                cvss_score=cvss_score,
                affected_url=affected_url,
                scanner=self.scanner_name,
            )
        except Exception:
            logger.exception("Failed to write finding to Firestore")
            return ""

    # ------------------------------------------------------------------
    # HTTP request helper
    # ------------------------------------------------------------------

    def make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        data: Any = None,
        *,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
    ) -> Optional[requests.Response]:
        """Make an HTTP request with built-in timeout, delay, and error
        handling.

        Parameters
        ----------
        url : str
            Target URL.
        method : str
            HTTP method (``GET``, ``POST``, etc.).
        headers : dict, optional
            Extra headers to merge with session defaults.
        data : any, optional
            Body payload (for POST/PUT).
        timeout : int, optional
            Per-request timeout in seconds.  Defaults to
            ``config.SCAN_TIMEOUT``.
        allow_redirects : bool
            Follow redirects (default ``True``).

        Returns
        -------
        requests.Response or None
            The response object, or ``None`` if the request failed.
        """
        if timeout is None:
            timeout = config.SCAN_TIMEOUT

        # Circuit Breaker: pause if target is unhealthy
        if self._circuit_breaker.is_open:
            self.log("warning", f"Circuit breaker OPEN - waiting {self._circuit_breaker.cooldown_seconds}s before retrying")
            time.sleep(self._circuit_breaker.cooldown_seconds)
            if self._circuit_breaker.is_open:
                self.log("error", "Circuit breaker still open after cooldown - skipping request")
                return None

        # Respect the configured delay between requests
        time.sleep(config.REQUEST_DELAY)

        merged_headers = dict(self._session.headers)
        if headers:
            merged_headers.update(headers)

        try:
            start_time = time.time()
            response = self._session.request(
                method=method.upper(),
                url=url,
                headers=merged_headers,
                data=data,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=True,
            )
            elapsed = time.time() - start_time
            self._circuit_breaker.record_success(elapsed)
            return response
        except requests.exceptions.Timeout:
            self._circuit_breaker.record_error()
            self.log("warning", f"Request timed out: {method} {url}")
            return None
        except requests.exceptions.ConnectionError:
            self._circuit_breaker.record_error()
            self.log("warning", f"Connection error: {method} {url}")
            return None
        except requests.exceptions.TooManyRedirects:
            self.log("warning", f"Too many redirects: {method} {url}")
            return None
        except requests.exceptions.RequestException as exc:
            self._circuit_breaker.record_error()
            self.log("error", f"Request failed: {method} {url} - {exc}")
            return None
