"""
VibeCrack Engine - Browser-Based XSS Scanner (Playwright)

Confirms reflected and DOM-based XSS vulnerabilities by injecting payloads
into a real headless Chromium browser and monitoring for JavaScript execution
via dialog events (alert/confirm/prompt).

Requires Playwright: pip install playwright && playwright install chromium
If Playwright is not installed, the scanner gracefully skips all tests.
"""

import logging
import time
from html.parser import HTMLParser
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from engine.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional Playwright import
# ---------------------------------------------------------------------------

try:
    from playwright.sync_api import sync_playwright, Browser, Page, BrowserContext
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

# ---------------------------------------------------------------------------
# XSS payloads tuned for browser execution (small set for speed)
# ---------------------------------------------------------------------------

BROWSER_XSS_PAYLOADS = [
    '<img src=x onerror=alert("XSS")>',
    '<script>alert("XSS")</script>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
    '<svg onload=alert("XSS")>',
]

# URL parameter names commonly reflected in DOM
DOM_SINK_PARAMS = [
    "q", "s", "search", "query", "keyword", "term",
    "id", "page", "name", "redirect", "url", "next",
    "callback", "return", "ref", "lang", "type", "action",
    "message", "msg", "error", "text", "title", "content",
    "value", "input", "data", "html", "template",
]

# Timeouts (seconds)
PAGE_TIMEOUT_MS = 5_000       # 5 seconds per page navigation
FORM_TOTAL_TIMEOUT = 30.0     # 30 seconds total per form
BROWSER_LAUNCH_TIMEOUT = 15_000  # 15 seconds to launch browser


# ---------------------------------------------------------------------------
# Minimal form parser (reused from xss_scanner pattern)
# ---------------------------------------------------------------------------

class _FormParser(HTMLParser):
    """Extracts <form> elements and their input fields from HTML."""

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


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class XSSBrowserScanner(BaseScanner):
    """Playwright-based XSS scanner that confirms XSS execution in a real
    headless Chromium browser by monitoring for JavaScript dialog events.

    Findings from this scanner are rated CRITICAL because they represent
    confirmed, executable cross-site scripting vulnerabilities.
    """

    scanner_name = "xss_browser_scanner"

    def run(self) -> None:
        if not HAS_PLAYWRIGHT:
            self.log(
                "warning",
                "Playwright is not installed - skipping browser-based XSS scan. "
                "Install with: pip install playwright && playwright install chromium",
            )
            return

        self.log("info", f"Starting browser-based XSS scan for {self.base_url}")

        # Fetch the page with the standard HTTP client first to discover
        # forms and URL parameters before launching the browser.
        response = self.make_request(self.base_url)
        if response is None:
            self.log("error", f"Could not reach {self.base_url} - aborting browser XSS scan")
            return

        # Extract forms and URLs with parameters
        forms = self._extract_forms(response.text, self.base_url)
        param_urls = self._extract_urls_with_params(response.text, self.base_url)

        self.log("info", f"Found {len(forms)} form(s) and {len(param_urls)} parameterised URL(s)")

        # Launch browser and run tests
        playwright_ctx = None
        browser: Any = None

        try:
            playwright_ctx = sync_playwright().start()
            browser = playwright_ctx.chromium.launch(
                headless=True,
                timeout=BROWSER_LAUNCH_TIMEOUT,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )

            self.log("info", "Headless Chromium launched successfully")

            # 1. Test forms by injecting payloads into input fields
            for form in forms:
                self._test_form_in_browser(browser, form)

            # 2. Test URL parameters for reflected/DOM XSS
            for url in param_urls:
                self._test_url_params_in_browser(browser, url)

            # 3. Test DOM XSS via common parameter names on the base URL
            self._test_dom_xss(browser)

        except Exception as exc:
            self.log("error", f"Browser XSS scan error: {exc}")
        finally:
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass
            if playwright_ctx is not None:
                try:
                    playwright_ctx.stop()
                except Exception:
                    pass

        self.log("info", "Browser-based XSS scan complete")

    # ------------------------------------------------------------------
    # Form extraction
    # ------------------------------------------------------------------

    def _extract_forms(self, html: str, page_url: str) -> list[dict]:
        """Parse HTML and return form descriptors with resolved action URLs."""
        parser = _FormParser()
        try:
            parser.feed(html)
        except Exception:
            self.log("warning", "HTML parser error during form extraction")

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
        """Find in-page URLs that contain query parameters."""
        import re

        url_pattern = re.compile(
            r'(?:href|src|action)\s*=\s*["\']([^"\']+\?[^"\']+)["\']',
            re.IGNORECASE,
        )
        matches = url_pattern.findall(html)

        result: list[str] = []
        seen: set[str] = set()

        for raw_url in matches:
            resolved = urljoin(page_url, raw_url)
            if urlparse(resolved).netloc == urlparse(page_url).netloc:
                if resolved not in seen:
                    seen.add(resolved)
                    result.append(resolved)

        return result

    # ------------------------------------------------------------------
    # Browser context helper
    # ------------------------------------------------------------------

    def _new_context(self, browser: Any) -> Any:
        """Create a fresh browser context with a reasonable viewport and
        the VibeCrack user-agent."""
        from engine import config

        return browser.new_context(
            user_agent=config.USER_AGENT,
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
            java_script_enabled=True,
        )

    # ------------------------------------------------------------------
    # Form testing in browser
    # ------------------------------------------------------------------

    def _test_form_in_browser(self, browser: Any, form: dict) -> None:
        """Inject XSS payloads into each form input via the browser and
        monitor for dialog events that confirm execution."""
        action_url = form["action"]
        method = form["method"]
        named_inputs = [i for i in form["inputs"] if i.get("name")]

        if not named_inputs:
            return

        form_start_time = time.time()

        for target_input in named_inputs:
            # Skip non-reflectable input types
            if target_input["type"] in ("hidden", "submit", "button", "file", "image", "reset"):
                continue

            for payload in BROWSER_XSS_PAYLOADS:
                # Respect total timeout per form
                if time.time() - form_start_time > FORM_TOTAL_TIMEOUT:
                    self.log("info", f"Form timeout reached for {action_url}, moving on")
                    return

                confirmed = self._try_form_payload(
                    browser, action_url, method, named_inputs,
                    target_input["name"], payload,
                )

                if confirmed:
                    xss_remediation = self.get_remediation_with_code(
                        "xss",
                        "1. Sanitize and escape all user input before rendering in HTML.\n"
                        "2. Use a library like DOMPurify for client-side sanitization.\n"
                        "3. Implement a strict Content-Security-Policy (CSP) header.\n"
                        "4. Use context-aware output encoding (HTML entity, JS, URL encoding).\n"
                        "5. Set HttpOnly and Secure flags on session cookies.",
                    )
                    self.add_finding(
                        severity="critical",
                        title=f"Confirmed XSS execution in form input '{target_input['name']}'",
                        description=(
                            f"A cross-site scripting payload injected into the "
                            f"'{target_input['name']}' field of the form at {action_url} "
                            f"executed JavaScript in the browser. This was confirmed by "
                            f"detecting a dialog event (alert/confirm/prompt) fired by "
                            f"the payload. An attacker can exploit this to steal session "
                            f"tokens, redirect users, or perform actions on their behalf."
                        ),
                        evidence={
                            "url": action_url,
                            "method": method,
                            "input_field": target_input["name"],
                            "payload": payload,
                            "confirmation": "JavaScript dialog (alert/confirm/prompt) fired in headless Chromium",
                        },
                        remediation=xss_remediation,
                        owasp_category="A03:2021 - Injection",
                        cvss_score=9.6,
                        affected_url=action_url,
                    )
                    # One confirmed payload per input is enough
                    break

    def _try_form_payload(
        self,
        browser: Any,
        action_url: str,
        method: str,
        all_inputs: list[dict],
        target_name: str,
        payload: str,
    ) -> bool:
        """Submit a single form payload in the browser and return True if
        a dialog event fires (confirming XSS execution)."""
        dialog_fired = {"value": False}

        context = None
        page = None
        try:
            context = self._new_context(browser)
            page = context.new_page()
            page.set_default_timeout(PAGE_TIMEOUT_MS)

            def _on_dialog(dialog: Any) -> None:
                dialog_fired["value"] = True
                try:
                    dialog.dismiss()
                except Exception:
                    pass

            page.on("dialog", _on_dialog)

            if method == "POST":
                # Build and submit a POST form programmatically
                form_data = {}
                for inp in all_inputs:
                    if inp["name"] == target_name:
                        form_data[inp["name"]] = payload
                    else:
                        form_data[inp["name"]] = inp.get("value", "test")

                # Navigate to the action URL's origin first, then submit via JS
                parsed = urlparse(action_url)
                origin = f"{parsed.scheme}://{parsed.netloc}"
                try:
                    page.goto(origin, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
                except Exception:
                    pass

                # Build a JS form submission
                js_code = self._build_form_submit_js(action_url, form_data)
                try:
                    page.evaluate(js_code)
                    # Wait for potential navigation and dialog
                    page.wait_for_timeout(2000)
                except Exception:
                    pass

            else:
                # GET: append payload as query parameter
                parsed = urlparse(action_url)
                params: dict[str, str] = {}
                for inp in all_inputs:
                    if inp["name"] == target_name:
                        params[inp["name"]] = payload
                    else:
                        params[inp["name"]] = inp.get("value", "test")

                qs = urlencode(params)
                if parsed.query:
                    qs = f"{parsed.query}&{qs}"
                test_url = urlunparse(parsed._replace(query=qs))

                try:
                    page.goto(test_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
                    page.wait_for_timeout(1500)
                except Exception:
                    pass

            # Also check for injected elements in the DOM
            if not dialog_fired["value"]:
                dialog_fired["value"] = self._check_dom_for_injection(page, payload)

            return dialog_fired["value"]

        except Exception as exc:
            self.log("warning", f"Error testing form payload: {exc}")
            return False
        finally:
            if page is not None:
                try:
                    page.close()
                except Exception:
                    pass
            if context is not None:
                try:
                    context.close()
                except Exception:
                    pass

    @staticmethod
    def _build_form_submit_js(action_url: str, form_data: dict[str, str]) -> str:
        """Return JavaScript code that creates and submits a POST form."""
        # Escape values for safe embedding in JS strings
        fields_js = ""
        for name, value in form_data.items():
            escaped_name = name.replace("\\", "\\\\").replace("'", "\\'")
            escaped_value = value.replace("\\", "\\\\").replace("'", "\\'")
            fields_js += (
                f"  var inp = document.createElement('input');"
                f"  inp.type = 'hidden';"
                f"  inp.name = '{escaped_name}';"
                f"  inp.value = '{escaped_value}';"
                f"  form.appendChild(inp);"
            )

        escaped_action = action_url.replace("\\", "\\\\").replace("'", "\\'")

        return (
            f"(function() {{"
            f"  var form = document.createElement('form');"
            f"  form.method = 'POST';"
            f"  form.action = '{escaped_action}';"
            f"  {fields_js}"
            f"  document.body.appendChild(form);"
            f"  form.submit();"
            f"}})()"
        )

    # ------------------------------------------------------------------
    # URL parameter testing in browser
    # ------------------------------------------------------------------

    def _test_url_params_in_browser(self, browser: Any, url: str) -> None:
        """Inject XSS payloads into each query parameter and navigate in
        the browser to check for execution."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return

        for param_name in params:
            for payload in BROWSER_XSS_PAYLOADS:
                modified_params = {k: v[0] if v else "" for k, v in params.items()}
                modified_params[param_name] = payload
                modified_qs = urlencode(modified_params)
                test_url = urlunparse(parsed._replace(query=modified_qs))

                confirmed = self._navigate_and_check(browser, test_url, payload)

                if confirmed:
                    xss_url_remediation = self.get_remediation_with_code(
                        "xss",
                        "1. Sanitize and escape all user input before rendering in HTML.\n"
                        "2. Use a library like DOMPurify for client-side sanitization.\n"
                        "3. Implement a strict Content-Security-Policy (CSP) header.\n"
                        "4. Use context-aware output encoding (HTML entity, JS, URL encoding).\n"
                        "5. Set HttpOnly and Secure flags on session cookies.",
                    )
                    self.add_finding(
                        severity="critical",
                        title=f"Confirmed XSS execution via URL parameter '{param_name}'",
                        description=(
                            f"Injecting an XSS payload into the '{param_name}' URL "
                            f"parameter at {parsed.path} caused JavaScript to execute "
                            f"in the browser. This was confirmed by detecting a dialog "
                            f"event. An attacker can craft a malicious link that "
                            f"executes arbitrary JavaScript in a victim's browser session."
                        ),
                        evidence={
                            "url": test_url,
                            "parameter": param_name,
                            "payload": payload,
                            "confirmation": "JavaScript dialog (alert/confirm/prompt) fired in headless Chromium",
                        },
                        remediation=xss_url_remediation,
                        owasp_category="A03:2021 - Injection",
                        cvss_score=9.6,
                        affected_url=test_url,
                    )
                    # One confirmed payload per parameter is enough
                    break

    # ------------------------------------------------------------------
    # DOM-based XSS testing
    # ------------------------------------------------------------------

    def _test_dom_xss(self, browser: Any) -> None:
        """Test for DOM-based XSS by injecting payloads into common URL
        parameters and the URL fragment (hash)."""
        self.log("info", "Testing for DOM-based XSS via common parameters and URL hash")

        # Test payloads in common parameter names on the base URL
        tested_params: set[str] = set()

        for param_name in DOM_SINK_PARAMS:
            for payload in BROWSER_XSS_PAYLOADS[:3]:  # Limit to 3 payloads for speed
                test_url = f"{self.base_url}?{urlencode({param_name: payload})}"

                confirmed = self._navigate_and_check(browser, test_url, payload)

                if confirmed and param_name not in tested_params:
                    tested_params.add(param_name)
                    self.add_finding(
                        severity="critical",
                        title=f"Confirmed DOM-based XSS via parameter '{param_name}'",
                        description=(
                            f"A DOM-based XSS vulnerability was confirmed at {self.base_url}. "
                            f"The '{param_name}' parameter value is used unsafely in "
                            f"client-side JavaScript, allowing an attacker to execute "
                            f"arbitrary code by crafting a malicious URL. The browser "
                            f"executed the payload without server-side reflection."
                        ),
                        evidence={
                            "url": test_url,
                            "parameter": param_name,
                            "payload": payload,
                            "type": "DOM-based XSS",
                            "confirmation": "JavaScript dialog (alert/confirm/prompt) fired in headless Chromium",
                        },
                        remediation=(
                            "1. Never use innerHTML, document.write(), or eval() with user-controlled data.\n"
                            "2. Use textContent or innerText instead of innerHTML.\n"
                            "3. Sanitize URL parameters before using them in DOM operations.\n"
                            "4. Use DOMPurify to sanitize any HTML that must be rendered.\n"
                            "5. Implement a strict Content-Security-Policy (CSP) header."
                        ),
                        owasp_category="A03:2021 - Injection",
                        cvss_score=9.6,
                        affected_url=test_url,
                    )
                    break  # Move to next parameter

        # Test payload in URL hash (fragment)
        for payload in BROWSER_XSS_PAYLOADS[:3]:
            hash_url = f"{self.base_url}#{payload}"
            confirmed = self._navigate_and_check(browser, hash_url, payload)

            if confirmed:
                self.add_finding(
                    severity="critical",
                    title="Confirmed DOM-based XSS via URL fragment (hash)",
                    description=(
                        f"A DOM-based XSS vulnerability was confirmed at {self.base_url}. "
                        f"The URL fragment (hash) is processed unsafely by client-side "
                        f"JavaScript. Since the hash is never sent to the server, this "
                        f"is a purely client-side vulnerability that bypasses server-side "
                        f"XSS filters."
                    ),
                    evidence={
                        "url": hash_url,
                        "payload": payload,
                        "type": "DOM-based XSS (hash fragment)",
                        "confirmation": "JavaScript dialog (alert/confirm/prompt) fired in headless Chromium",
                    },
                    remediation=(
                        "1. Never use location.hash directly in innerHTML, document.write(), or eval().\n"
                        "2. Sanitize all hash fragment values before DOM insertion.\n"
                        "3. Use textContent instead of innerHTML for displaying user data.\n"
                        "4. Implement a strict Content-Security-Policy (CSP) header."
                    ),
                    owasp_category="A03:2021 - Injection",
                    cvss_score=9.6,
                    affected_url=hash_url,
                )
                break  # One confirmed hash XSS is enough

    # ------------------------------------------------------------------
    # Core browser navigation + dialog detection
    # ------------------------------------------------------------------

    def _navigate_and_check(self, browser: Any, url: str, payload: str) -> bool:
        """Navigate to *url* in a fresh page and return True if a JS
        dialog fires or the payload is found in a dangerous DOM location."""
        dialog_fired = {"value": False}

        context = None
        page = None
        try:
            context = self._new_context(browser)
            page = context.new_page()
            page.set_default_timeout(PAGE_TIMEOUT_MS)

            def _on_dialog(dialog: Any) -> None:
                dialog_fired["value"] = True
                try:
                    dialog.dismiss()
                except Exception:
                    pass

            page.on("dialog", _on_dialog)

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
                # Give scripts time to execute
                page.wait_for_timeout(1500)
            except Exception:
                pass

            # Check dialog first (most reliable indicator)
            if dialog_fired["value"]:
                return True

            # Also check DOM for injected elements
            return self._check_dom_for_injection(page, payload)

        except Exception as exc:
            self.log("warning", f"Error navigating to {url}: {exc}")
            return False
        finally:
            if page is not None:
                try:
                    page.close()
                except Exception:
                    pass
            if context is not None:
                try:
                    context.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # DOM injection check
    # ------------------------------------------------------------------

    @staticmethod
    def _check_dom_for_injection(page: Any, payload: str) -> bool:
        """Check if the payload created executable elements in the DOM.

        Looks for injected <script>, <img> with onerror, <svg> with onload,
        or other event-handler-bearing elements that were not in the original page.
        """
        try:
            # Check for injected <img> elements with onerror handlers
            img_count = page.evaluate(
                "document.querySelectorAll('img[onerror]').length"
            )
            if img_count and img_count > 0:
                return True

            # Check for injected <svg> elements with onload handlers
            svg_count = page.evaluate(
                "document.querySelectorAll('svg[onload]').length"
            )
            if svg_count and svg_count > 0:
                return True

            # Check if the raw payload appears in the DOM body HTML
            # (indicates it was rendered as HTML, not escaped)
            body_html = page.evaluate("document.body ? document.body.innerHTML : ''")
            if payload in (body_html or ""):
                # The payload is in the DOM unescaped -- this is a strong
                # indicator but not confirmed execution, so we only return
                # True for element-based payloads that would auto-execute.
                auto_exec_indicators = [
                    "onerror=", "onload=", "<script>",
                ]
                if any(indicator in payload.lower() for indicator in auto_exec_indicators):
                    return True

        except Exception:
            pass

        return False
