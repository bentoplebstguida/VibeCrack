"""
HackerPA Engine - Cross-Site Scripting (XSS) Scanner

Tests for reflected XSS vulnerabilities by injecting payloads from
config.XSS_PAYLOADS into form inputs and URL parameters, then checking
whether the payload appears unescaped in the server response.

Non-destructive: only tests for reflection, never attempts stored XSS.
"""

import re
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

from engine import config
from engine.scanners.base_scanner import BaseScanner


class _FormParser(HTMLParser):
    """Minimal HTML parser that extracts <form> elements and their inputs."""

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

        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attr_dict.get("name", ""),
                "type": attr_dict.get("type", "text"),
                "value": attr_dict.get("value", ""),
            })

        elif tag == "textarea" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attr_dict.get("name", ""),
                "type": "textarea",
                "value": "",
            })

        elif tag == "select" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attr_dict.get("name", ""),
                "type": "select",
                "value": "",
            })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class XSSScanner(BaseScanner):
    """Reflected XSS scanner.

    Discovers forms and URL parameters on the target, then injects XSS
    payloads to determine whether they are reflected unescaped in the
    response body.
    """

    scanner_name = "xss_scanner"

    # Maximum number of payloads to test per injection point to stay
    # within a reasonable request budget.
    _MAX_PAYLOADS_PER_POINT = len(config.XSS_PAYLOADS)

    def run(self) -> None:
        self.log("info", f"Starting XSS scan for {self.base_url}")

        response = self.make_request(self.base_url)
        if response is None:
            self.log("error", f"Could not reach {self.base_url} - aborting XSS scan")
            return

        # ------------------------------------------------------------------
        # 1. Parse forms from the main page
        # ------------------------------------------------------------------
        forms = self._extract_forms(response.text, self.base_url)
        self.log("info", f"Found {len(forms)} form(s) on {self.base_url}")

        for form in forms:
            self._test_form_xss(form)

        # ------------------------------------------------------------------
        # 2. Test URL parameters already present in the response
        # ------------------------------------------------------------------
        urls_with_params = self._extract_urls_with_params(response.text, self.base_url)
        self.log("info", f"Found {len(urls_with_params)} URL(s) with parameters to test")

        for url in urls_with_params:
            self._test_url_params_xss(url)

        self.log("info", "XSS scan complete")

    # ------------------------------------------------------------------
    # Form extraction
    # ------------------------------------------------------------------

    def _extract_forms(self, html: str, page_url: str) -> list[dict]:
        """Parse HTML and return a list of form descriptors."""
        parser = _FormParser()
        try:
            parser.feed(html)
        except Exception:
            self.log("warning", "HTML parser encountered an error; partial form list may be used")

        # Resolve relative action URLs
        for form in parser.forms:
            action = form["action"]
            if not action:
                form["action"] = page_url
            elif not action.startswith(("http://", "https://")):
                form["action"] = urljoin(page_url, action)

        return parser.forms

    # ------------------------------------------------------------------
    # URL parameter extraction
    # ------------------------------------------------------------------

    def _extract_urls_with_params(self, html: str, page_url: str) -> list[str]:
        """Find all URLs in the page that contain query parameters."""
        # Match href="...", src="...", action="..."
        url_pattern = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+\?[^"\']+)["\']', re.IGNORECASE)
        matches = url_pattern.findall(html)

        result: list[str] = []
        seen: set[str] = set()

        for raw_url in matches:
            resolved = urljoin(page_url, raw_url)
            # Only test URLs on the same domain
            if urlparse(resolved).netloc == urlparse(page_url).netloc:
                if resolved not in seen:
                    seen.add(resolved)
                    result.append(resolved)

        return result

    # ------------------------------------------------------------------
    # XSS testing: forms
    # ------------------------------------------------------------------

    def _test_form_xss(self, form: dict) -> None:
        """Inject XSS payloads into every input of *form*."""
        action_url = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        # Skip forms with no named inputs
        named_inputs = [i for i in inputs if i.get("name")]
        if not named_inputs:
            return

        for target_input in named_inputs:
            # Skip hidden, submit, button, file inputs -- they are less
            # likely to be reflected and modifying them might be destructive.
            if target_input["type"] in ("hidden", "submit", "button", "file", "image", "reset"):
                continue

            for payload in config.XSS_PAYLOADS[:self._MAX_PAYLOADS_PER_POINT]:
                # Build the form data: fill other fields with benign values
                form_data: dict[str, str] = {}
                for inp in named_inputs:
                    if inp["name"] == target_input["name"]:
                        form_data[inp["name"]] = payload
                    else:
                        form_data[inp["name"]] = inp.get("value", "test")

                resp = self._submit_form(action_url, method, form_data)
                if resp is None:
                    continue

                if self._payload_reflected(payload, resp.text):
                    snippet = self._extract_snippet(payload, resp.text)
                    self.add_finding(
                        severity="high",
                        title=f"Reflected XSS in form input '{target_input['name']}'",
                        description=(
                            f"The form at {action_url} reflects the XSS payload "
                            f"unescaped in the response when submitted via {method} "
                            f"in the '{target_input['name']}' field. An attacker "
                            f"could craft a malicious URL or form submission to "
                            f"execute arbitrary JavaScript in a victim's browser."
                        ),
                        evidence={
                            "url": action_url,
                            "payload": payload,
                            "response_snippet": snippet,
                        },
                        remediation=(
                            "1. Sanitize and escape all user input before rendering in HTML.\n"
                            "2. Use a library like DOMPurify for client-side sanitization.\n"
                            "3. Implement a strict Content-Security-Policy (CSP) header.\n"
                            "4. Use context-aware output encoding (HTML entity, JS, URL encoding).\n"
                            "5. Set HttpOnly and Secure flags on session cookies."
                        ),
                        owasp_category="A03:2021 - Injection",
                        cvss_score=6.1,
                        affected_url=action_url,
                    )
                    # One confirmed payload per input is enough; move on
                    break

    def _submit_form(self, action_url: str, method: str, data: dict) -> Optional[requests.Response]:
        """Submit form data using the appropriate HTTP method."""
        if method == "POST":
            return self.make_request(action_url, method="POST", data=data)
        else:
            # GET: append data as query string
            parsed = urlparse(action_url)
            qs = urlencode(data)
            # Merge with any existing query string
            if parsed.query:
                qs = f"{parsed.query}&{qs}"
            url = urlunparse(parsed._replace(query=qs))
            return self.make_request(url)

    # ------------------------------------------------------------------
    # XSS testing: URL parameters
    # ------------------------------------------------------------------

    def _test_url_params_xss(self, url: str) -> None:
        """Inject XSS payloads into each query parameter of *url*."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return

        for param_name in params:
            for payload in config.XSS_PAYLOADS[:self._MAX_PAYLOADS_PER_POINT]:
                # Replace only this parameter with the payload
                modified_params = {k: v[0] if v else "" for k, v in params.items()}
                modified_params[param_name] = payload
                modified_qs = urlencode(modified_params)
                test_url = urlunparse(parsed._replace(query=modified_qs))

                resp = self.make_request(test_url)
                if resp is None:
                    continue

                if self._payload_reflected(payload, resp.text):
                    snippet = self._extract_snippet(payload, resp.text)
                    self.add_finding(
                        severity="high",
                        title=f"Reflected XSS via URL parameter '{param_name}'",
                        description=(
                            f"The URL parameter '{param_name}' at {parsed.path} "
                            f"reflects the injected XSS payload unescaped in the "
                            f"response. An attacker can craft a malicious link that "
                            f"executes JavaScript in the victim's browser."
                        ),
                        evidence={
                            "url": test_url,
                            "payload": payload,
                            "response_snippet": snippet,
                        },
                        remediation=(
                            "1. Sanitize and escape all user input before rendering in HTML.\n"
                            "2. Use a library like DOMPurify for client-side sanitization.\n"
                            "3. Implement a strict Content-Security-Policy (CSP) header.\n"
                            "4. Use context-aware output encoding (HTML entity, JS, URL encoding).\n"
                            "5. Set HttpOnly and Secure flags on session cookies."
                        ),
                        owasp_category="A03:2021 - Injection",
                        cvss_score=6.1,
                        affected_url=test_url,
                    )
                    # One confirmed payload per parameter is enough
                    break

    # ------------------------------------------------------------------
    # Reflection detection helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _payload_reflected(payload: str, response_body: str) -> bool:
        """Return True if *payload* appears unescaped in *response_body*."""
        return payload in response_body

    @staticmethod
    def _extract_snippet(payload: str, response_body: str, context: int = 80) -> str:
        """Return the portion of *response_body* surrounding the reflected
        payload, capped to roughly *context* characters on each side."""
        idx = response_body.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - context)
        end = min(len(response_body), idx + len(payload) + context)
        snippet = response_body[start:end]
        if start > 0:
            snippet = "..." + snippet
        if end < len(response_body):
            snippet = snippet + "..."
        return snippet
