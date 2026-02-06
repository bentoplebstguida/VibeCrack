"""
HackerPA Engine - SQL Injection Scanner

Tests for SQL injection vulnerabilities using three detection techniques:
  1. Error-based: Inject payloads and look for SQL error messages.
  2. Blind boolean-based: Compare response lengths for TRUE vs FALSE conditions.
  3. Time-based blind: Inject SLEEP/WAITFOR and measure response time.

NON-DESTRUCTIVE: Only attempts to prove injection is possible.  Never
drops, deletes, or modifies data on the target.
"""

import re
import time
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

from engine import config
from engine.scanners.base_scanner import BaseScanner


# -------------------------------------------------------------------
# SQL error signatures for major database engines
# -------------------------------------------------------------------
SQL_ERROR_PATTERNS: list[re.Pattern] = [
    # MySQL
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning:.*mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"mysql_fetch", re.IGNORECASE),
    re.compile(r"mysqli?[_\.]", re.IGNORECASE),
    # PostgreSQL
    re.compile(r"pg_query\(\)", re.IGNORECASE),
    re.compile(r"pg_exec\(\)", re.IGNORECASE),
    re.compile(r"PSQLException", re.IGNORECASE),
    re.compile(r"unterminated quoted string", re.IGNORECASE),
    re.compile(r"syntax error at or near", re.IGNORECASE),
    # Microsoft SQL Server
    re.compile(r"microsoft ole db provider for sql server", re.IGNORECASE),
    re.compile(r"sql server.*driver", re.IGNORECASE),
    re.compile(r"microsoft sql native client", re.IGNORECASE),
    re.compile(r"\[SQLServer\]", re.IGNORECASE),
    re.compile(r"ODBC SQL Server Driver", re.IGNORECASE),
    # Oracle
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"oracle.*driver", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    # SQLite
    re.compile(r"SQLite.*error", re.IGNORECASE),
    re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
    re.compile(r"SQLITE_ERROR", re.IGNORECASE),
    # Generic
    re.compile(r"SQL syntax.*error", re.IGNORECASE),
    re.compile(r"unexpected end of SQL command", re.IGNORECASE),
    re.compile(r"invalid query", re.IGNORECASE),
    re.compile(r"SQL command not properly ended", re.IGNORECASE),
]

# Payloads used exclusively for error-based detection.  These are drawn
# from config but we also skip the DROP TABLE payload since it is
# destructive.
_SAFE_ERROR_PAYLOADS = [p for p in config.SQLI_PAYLOADS if "DROP" not in p.upper()]

# Boolean-based payload pairs (TRUE condition, FALSE condition)
_BOOLEAN_PAIRS: list[tuple[str, str]] = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("' AND 'a'='a'--", "' AND 'a'='b'--"),
]

# Time-based payloads and the minimum delay (seconds) we expect
_TIME_PAYLOADS: list[tuple[str, float]] = [
    ("' AND SLEEP(5)--", 4.0),
    ("' WAITFOR DELAY '0:0:5'--", 4.0),
    ("'; SELECT pg_sleep(5);--", 4.0),
]


class _FormParser(HTMLParser):
    """Extracts <form> elements and their <input>/<textarea>/<select> children."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._current_form: Optional[dict] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr_dict = dict(attrs)

        if tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": (attr_dict.get("method", "GET")).upper(),
                "inputs": [],
            }
        elif self._current_form is not None and tag in ("input", "textarea", "select"):
            self._current_form["inputs"].append({
                "name": attr_dict.get("name", ""),
                "type": attr_dict.get("type", "text"),
                "value": attr_dict.get("value", ""),
            })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class SQLiScanner(BaseScanner):
    """SQL Injection scanner.

    Discovers injection points (form fields, URL parameters) and applies
    error-based, blind boolean-based, and time-based blind detection
    techniques.  All payloads are non-destructive.
    """

    scanner_name = "sqli_scanner"

    # Response-length difference ratio used for boolean-based detection.
    # If the ratio between the TRUE and FALSE responses differs by more
    # than this fraction, the parameter may be injectable.
    _BOOLEAN_LENGTH_THRESHOLD = 0.15

    def run(self) -> None:
        self.log("info", f"Starting SQL injection scan for {self.base_url}")

        response = self.make_request(self.base_url)
        if response is None:
            self.log("error", f"Could not reach {self.base_url} - aborting SQLi scan")
            return

        # Gather a baseline response length for the homepage
        self._baseline_length = len(response.text)

        # 1. Extract forms
        forms = self._extract_forms(response.text, self.base_url)
        self.log("info", f"Found {len(forms)} form(s) on {self.base_url}")

        for form in forms:
            self._test_form(form)

        # 2. Extract URL parameters from links on the page
        urls = self._extract_urls_with_params(response.text, self.base_url)
        self.log("info", f"Found {len(urls)} URL(s) with parameters to test")

        for url in urls:
            self._test_url_params(url)

        self.log("info", "SQL injection scan complete")

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    def _extract_forms(self, html: str, page_url: str) -> list[dict]:
        parser = _FormParser()
        try:
            parser.feed(html)
        except Exception:
            self.log("warning", "HTML parser error; partial form list may be used")

        for form in parser.forms:
            action = form["action"]
            if not action:
                form["action"] = page_url
            elif not action.startswith(("http://", "https://")):
                form["action"] = urljoin(page_url, action)
        return parser.forms

    def _extract_urls_with_params(self, html: str, page_url: str) -> list[str]:
        pattern = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+\?[^"\']+)["\']', re.IGNORECASE)
        matches = pattern.findall(html)
        seen: set[str] = set()
        result: list[str] = []
        for raw in matches:
            resolved = urljoin(page_url, raw)
            if urlparse(resolved).netloc == urlparse(page_url).netloc and resolved not in seen:
                seen.add(resolved)
                result.append(resolved)
        return result

    # ------------------------------------------------------------------
    # Form testing
    # ------------------------------------------------------------------

    def _test_form(self, form: dict) -> None:
        action_url = form["action"]
        method = form["method"]
        named_inputs = [i for i in form["inputs"] if i.get("name")]
        if not named_inputs:
            return

        for target_input in named_inputs:
            if target_input["type"] in ("hidden", "submit", "button", "file", "image", "reset"):
                continue

            self._test_injection_point(
                label=f"form input '{target_input['name']}'",
                build_request=lambda payload, _ti=target_input, _ni=named_inputs: self._build_form_request(
                    action_url, method, _ni, _ti["name"], payload
                ),
                affected_url=action_url,
            )

    def _build_form_request(
        self,
        action_url: str,
        method: str,
        all_inputs: list[dict],
        target_name: str,
        payload: str,
    ) -> tuple[str, str, Optional[dict]]:
        """Return ``(url, http_method, data_or_none)`` ready for ``make_request``."""
        form_data: dict[str, str] = {}
        for inp in all_inputs:
            if inp["name"] == target_name:
                form_data[inp["name"]] = payload
            else:
                form_data[inp["name"]] = inp.get("value", "test")

        if method == "POST":
            return action_url, "POST", form_data
        else:
            parsed = urlparse(action_url)
            qs = urlencode(form_data)
            if parsed.query:
                qs = f"{parsed.query}&{qs}"
            return urlunparse(parsed._replace(query=qs)), "GET", None

    # ------------------------------------------------------------------
    # URL parameter testing
    # ------------------------------------------------------------------

    def _test_url_params(self, url: str) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        for param_name in params:
            def build_request(payload: str, _pn=param_name, _p=parsed, _params=params):
                modified = {k: v[0] if v else "" for k, v in _params.items()}
                modified[_pn] = payload
                test_url = urlunparse(_p._replace(query=urlencode(modified)))
                return test_url, "GET", None

            self._test_injection_point(
                label=f"URL parameter '{param_name}'",
                build_request=build_request,
                affected_url=url,
            )

    # ------------------------------------------------------------------
    # Core injection test (combines all three techniques)
    # ------------------------------------------------------------------

    def _test_injection_point(
        self,
        label: str,
        build_request,
        affected_url: str,
    ) -> None:
        """Run all three detection techniques against a single injection
        point identified by *label*.

        ``build_request`` is a callable that takes a payload string and
        returns ``(url, method, data_or_none)``.
        """
        # ----- 1. Error-based detection ---------------------------------
        for payload in _SAFE_ERROR_PAYLOADS:
            url, method, data = build_request(payload)
            resp = self.make_request(url, method=method, data=data)
            if resp is None:
                continue

            error_msg = self._find_sql_error(resp.text)
            if error_msg:
                snippet = self._extract_snippet(error_msg, resp.text)
                sqli_remediation = self.get_remediation_with_code("sqli",
                    "1. Use parameterized queries / prepared statements -- never "
                    "concatenate user input into SQL.\n"
                    "2. Use an ORM (e.g. SQLAlchemy, Sequelize, ActiveRecord) "
                    "which parameterizes by default.\n"
                    "3. Apply the principle of least privilege to database accounts.\n"
                    "4. Validate and sanitize all user-supplied input.\n"
                    "5. Disable detailed error messages in production.")
                self.add_finding(
                    severity="critical",
                    title=f"SQL Injection (error-based) in {label}",
                    description=(
                        f"The {label} at {affected_url} is vulnerable to SQL "
                        f"injection. When the payload was submitted, the server "
                        f"responded with a SQL error message, confirming that "
                        f"user input is concatenated into SQL queries without "
                        f"sanitization."
                    ),
                    evidence={
                        "url": url,
                        "payload": payload,
                        "response_snippet": snippet,
                    },
                    remediation=sqli_remediation,
                    owasp_category="A03:2021 - Injection",
                    cvss_score=9.8,
                    affected_url=affected_url,
                )
                return  # One confirmed finding per injection point is sufficient

        # ----- 2. Blind boolean-based detection -------------------------
        for true_payload, false_payload in _BOOLEAN_PAIRS:
            url_t, method_t, data_t = build_request(true_payload)
            resp_true = self.make_request(url_t, method=method_t, data=data_t)
            if resp_true is None:
                continue

            url_f, method_f, data_f = build_request(false_payload)
            resp_false = self.make_request(url_f, method=method_f, data=data_f)
            if resp_false is None:
                continue

            len_true = len(resp_true.text)
            len_false = len(resp_false.text)

            # If the responses differ significantly, the parameter is
            # likely influencing a SQL WHERE clause.
            if len_true > 0 and len_false > 0:
                diff_ratio = abs(len_true - len_false) / max(len_true, len_false)
                if diff_ratio > self._BOOLEAN_LENGTH_THRESHOLD and resp_true.status_code == resp_false.status_code:
                    sqli_bool_remediation = self.get_remediation_with_code("sqli",
                        "1. Use parameterized queries / prepared statements -- never "
                        "concatenate user input into SQL.\n"
                        "2. Use an ORM which parameterizes by default.\n"
                        "3. Apply the principle of least privilege to database accounts.\n"
                        "4. Validate and sanitize all user-supplied input.")
                    self.add_finding(
                        severity="high",
                        title=f"SQL Injection (blind boolean-based) in {label}",
                        description=(
                            f"The {label} at {affected_url} appears vulnerable to "
                            f"blind boolean-based SQL injection. The TRUE condition "
                            f"({true_payload}) returned {len_true} bytes while the "
                            f"FALSE condition ({false_payload}) returned {len_false} "
                            f"bytes, a {diff_ratio:.0%} difference, suggesting the "
                            f"injected condition is being evaluated by the database."
                        ),
                        evidence={
                            "url": url_t,
                            "payload": f"TRUE: {true_payload} ({len_true}B) vs FALSE: {false_payload} ({len_false}B)",
                            "response_snippet": (
                                f"TRUE response length: {len_true} bytes | "
                                f"FALSE response length: {len_false} bytes | "
                                f"Difference ratio: {diff_ratio:.2%}"
                            ),
                        },
                        remediation=sqli_bool_remediation,
                        owasp_category="A03:2021 - Injection",
                        cvss_score=8.6,
                        affected_url=affected_url,
                    )
                    return

        # ----- 3. Time-based blind detection ----------------------------
        for payload, min_delay in _TIME_PAYLOADS:
            url, method, data = build_request(payload)

            start = time.time()
            resp = self.make_request(url, method=method, data=data, timeout=15)
            elapsed = time.time() - start

            if resp is None:
                # A timeout might itself be evidence of a sleep succeeding,
                # but we cannot be certain, so we just skip.
                continue

            if elapsed >= min_delay:
                sqli_time_remediation = self.get_remediation_with_code("sqli",
                    "1. Use parameterized queries / prepared statements -- never "
                    "concatenate user input into SQL.\n"
                    "2. Use an ORM which parameterizes by default.\n"
                    "3. Apply the principle of least privilege to database accounts.\n"
                    "4. Validate and sanitize all user-supplied input.")
                self.add_finding(
                    severity="high",
                    title=f"SQL Injection (time-based blind) in {label}",
                    description=(
                        f"The {label} at {affected_url} appears vulnerable to "
                        f"time-based blind SQL injection. The payload '{payload}' "
                        f"caused a response delay of {elapsed:.1f}s (expected "
                        f">= {min_delay:.0f}s), suggesting the injected SLEEP/"
                        f"WAITFOR command is being executed by the database."
                    ),
                    evidence={
                        "url": url,
                        "payload": payload,
                        "response_snippet": (
                            f"Response time: {elapsed:.2f}s (baseline expected <2s). "
                            f"Injected delay: {min_delay:.0f}s."
                        ),
                    },
                    remediation=sqli_time_remediation,
                    owasp_category="A03:2021 - Injection",
                    cvss_score=8.6,
                    affected_url=affected_url,
                )
                return

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_sql_error(response_body: str) -> Optional[str]:
        """Return the first SQL error message found in *response_body*, or
        ``None`` if none is detected."""
        for pattern in SQL_ERROR_PATTERNS:
            match = pattern.search(response_body)
            if match:
                return match.group(0)
        return None

    @staticmethod
    def _extract_snippet(needle: str, haystack: str, context: int = 100) -> str:
        """Return the portion of *haystack* surrounding *needle*."""
        idx = haystack.lower().find(needle.lower())
        if idx == -1:
            return needle
        start = max(0, idx - context)
        end = min(len(haystack), idx + len(needle) + context)
        snippet = haystack[start:end]
        if start > 0:
            snippet = "..." + snippet
        if end < len(haystack):
            snippet = snippet + "..."
        return snippet
