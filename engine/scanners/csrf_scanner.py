"""
VibeCrack Engine - Cross-Site Request Forgery (CSRF) Scanner

Fetches pages and inspects every <form> for CSRF protection mechanisms:
  - Hidden inputs with CSRF token names (csrf_token, _token, etc.)
  - SameSite attribute on session cookies
  - Custom anti-CSRF headers (X-CSRF-Token, X-XSRF-TOKEN, etc.)

Reports forms that lack adequate protection as vulnerabilities.
"""

import re
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin

from engine.scanners.base_scanner import BaseScanner


# Hidden input names commonly used for CSRF tokens
CSRF_TOKEN_NAMES: set[str] = {
    "csrf_token",
    "csrftoken",
    "csrf",
    "_token",
    "_csrf",
    "_csrf_token",
    "csrfmiddlewaretoken",      # Django
    "authenticity_token",        # Ruby on Rails
    "__requestverificationtoken",  # ASP.NET
    "antiforgery",
    "__antiforgerytoken",
    "xsrf_token",
    "_xsrf",
    "token",
}

# Headers that can serve as CSRF protection when validated server-side
CSRF_HEADERS: list[str] = [
    "X-CSRF-Token",
    "X-XSRF-TOKEN",
    "X-Requested-With",
]


class _FormParser(HTMLParser):
    """Extracts <form> elements with their method, action, and all child
    <input> elements (especially hidden ones)."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._current_form: Optional[dict] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr_dict = {k.lower(): v for k, v in attrs}

        if tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": (attr_dict.get("method", "GET")).upper(),
                "inputs": [],
                "id": attr_dict.get("id", ""),
                "name": attr_dict.get("name", ""),
            }
        elif self._current_form is not None and tag == "input":
            self._current_form["inputs"].append({
                "name": (attr_dict.get("name") or "").lower(),
                "type": (attr_dict.get("type") or "text").lower(),
                "value": attr_dict.get("value", ""),
            })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class CSRFScanner(BaseScanner):
    """CSRF protection scanner.

    Inspects forms for CSRF tokens and checks cookie attributes and
    response headers that can mitigate CSRF attacks.
    """

    scanner_name = "csrf_scanner"

    def run(self) -> None:
        self.log("info", f"Starting CSRF scan for {self.base_url}")

        response = self.make_request(self.base_url)
        if response is None:
            self.log("error", f"Could not reach {self.base_url} - aborting CSRF scan")
            return

        # ------------------------------------------------------------------
        # 1. Analyse cookies for SameSite attribute
        # ------------------------------------------------------------------
        samesite_protected = self._check_samesite_cookies(response)

        # ------------------------------------------------------------------
        # 2. Check for CSRF-related response headers
        # ------------------------------------------------------------------
        has_csrf_header = self._check_csrf_headers(response)

        # ------------------------------------------------------------------
        # 3. Parse forms and check for CSRF tokens
        # ------------------------------------------------------------------
        forms = self._extract_forms(response.text, self.base_url)
        self.log("info", f"Found {len(forms)} form(s) on {self.base_url}")

        # Also look for meta-tag based CSRF tokens (common in Laravel, Rails)
        meta_csrf = self._check_meta_csrf_token(response.text)

        state_changing_forms = [f for f in forms if f["method"] == "POST"]
        self.log("info", f"Found {len(state_changing_forms)} POST form(s) to inspect for CSRF tokens")

        for form in state_changing_forms:
            self._check_form_csrf(
                form,
                samesite_protected=samesite_protected,
                has_csrf_header=has_csrf_header,
                meta_csrf_present=meta_csrf,
            )

        # Report GET forms that appear to perform state changes
        for form in forms:
            if form["method"] == "GET":
                self._check_get_form_state_change(form)

        self.log("info", "CSRF scan complete")

    # ------------------------------------------------------------------
    # Cookie checks
    # ------------------------------------------------------------------

    def _check_samesite_cookies(self, response) -> bool:
        """Check whether session cookies have the SameSite attribute.

        Returns True if at least one cookie has SameSite=Strict or Lax.
        """
        cookies_with_samesite: list[str] = []
        cookies_without_samesite: list[str] = []

        set_cookie_headers = response.headers.get("Set-Cookie", "")
        # The headers object may collapse multiple Set-Cookie headers;
        # also try the raw headers via response.raw if available.
        raw_cookies: list[str] = []
        if hasattr(response, "headers") and hasattr(response.headers, "getlist"):
            raw_cookies = response.headers.getlist("Set-Cookie")
        elif set_cookie_headers:
            # Heuristic split when getlist is not available
            raw_cookies = [set_cookie_headers]

        for cookie_str in raw_cookies:
            cookie_lower = cookie_str.lower()
            # Extract cookie name
            name = cookie_str.split("=", 1)[0].strip()
            if "samesite=strict" in cookie_lower or "samesite=lax" in cookie_lower:
                cookies_with_samesite.append(name)
            elif "samesite=none" in cookie_lower:
                cookies_without_samesite.append(name)
            else:
                cookies_without_samesite.append(name)

        if cookies_without_samesite:
            self.add_finding(
                severity="medium",
                title="Session cookies missing SameSite attribute",
                description=(
                    f"The following cookies are set without a protective "
                    f"SameSite attribute (Strict or Lax): "
                    f"{', '.join(cookies_without_samesite)}. Without SameSite, "
                    f"browsers may send these cookies on cross-origin requests, "
                    f"enabling CSRF attacks."
                ),
                evidence={
                    "url": self.base_url,
                    "payload": "N/A",
                    "response_snippet": f"Set-Cookie headers: {'; '.join(raw_cookies)[:300]}",
                },
                remediation=self.get_remediation_with_code("csrf",
                    "1. Set the SameSite attribute to 'Lax' (minimum) or 'Strict' "
                    "on all session/authentication cookies.\n"
                    "2. Example: Set-Cookie: session=abc; SameSite=Lax; Secure; HttpOnly\n"
                    "3. Note: SameSite=None requires the Secure flag and sends the "
                    "cookie on all cross-site requests (no CSRF protection)."),
                owasp_category="A01:2021 - Broken Access Control",
                cvss_score=5.4,
                affected_url=self.base_url,
            )
            return False

        return bool(cookies_with_samesite)

    # ------------------------------------------------------------------
    # Header checks
    # ------------------------------------------------------------------

    def _check_csrf_headers(self, response) -> bool:
        """Check if the response indicates the server expects custom
        CSRF headers on state-changing requests."""
        for header_name in CSRF_HEADERS:
            if response.headers.get(header_name):
                self.log("info", f"CSRF header detected in response: {header_name}")
                return True
        return False

    # ------------------------------------------------------------------
    # Meta tag CSRF token
    # ------------------------------------------------------------------

    @staticmethod
    def _check_meta_csrf_token(html: str) -> bool:
        """Return True if the HTML contains a <meta> CSRF token tag.

        Common patterns:
          - <meta name="csrf-token" content="...">
          - <meta name="_token" content="...">
        """
        pattern = re.compile(
            r'<meta\s+[^>]*name\s*=\s*["\']'
            r'(csrf[-_]?token|_token|csrfmiddlewaretoken|xsrf[-_]?token)'
            r'["\'][^>]*>',
            re.IGNORECASE,
        )
        return bool(pattern.search(html))

    # ------------------------------------------------------------------
    # Form extraction
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

    # ------------------------------------------------------------------
    # Per-form CSRF check
    # ------------------------------------------------------------------

    def _check_form_csrf(
        self,
        form: dict,
        *,
        samesite_protected: bool,
        has_csrf_header: bool,
        meta_csrf_present: bool,
    ) -> None:
        """Check whether a POST *form* is protected against CSRF."""
        action_url = form["action"]
        form_id = form.get("id") or form.get("name") or action_url

        # Look for a CSRF token among hidden inputs
        has_hidden_token = False
        for inp in form["inputs"]:
            if inp["type"] == "hidden" and inp["name"] in CSRF_TOKEN_NAMES:
                has_hidden_token = True
                break

        # If there is a hidden token OR a meta-level token, the form is
        # considered protected (assuming JS injects it into the request).
        if has_hidden_token or meta_csrf_present:
            self.log("info", f"Form '{form_id}' has CSRF token protection")
            return

        # Even without a token, SameSite cookies can mitigate CSRF in
        # modern browsers.  We still report it as low severity because
        # not all browsers support SameSite equally.
        if samesite_protected:
            self.add_finding(
                severity="low",
                title=f"POST form lacks CSRF token (SameSite cookies present)",
                description=(
                    f"The POST form (action: {action_url}) does not contain a "
                    f"CSRF token. However, session cookies use the SameSite "
                    f"attribute, which provides partial protection in modern "
                    f"browsers. Defense-in-depth recommends also using tokens."
                ),
                evidence={
                    "url": action_url,
                    "payload": "N/A",
                    "response_snippet": self._form_summary(form),
                },
                remediation=self.get_remediation_with_code("csrf",
                    "1. Add a hidden CSRF token to every state-changing form.\n"
                    "2. Validate the token server-side on every POST request.\n"
                    "3. Use framework-provided CSRF protection (e.g. Django "
                    "{% csrf_token %}, Rails authenticity_token, Laravel @csrf)."),
                owasp_category="A01:2021 - Broken Access Control",
                cvss_score=4.3,
                affected_url=action_url,
            )
            return

        # No token and no SameSite protection -- high severity
        self.add_finding(
            severity="high",
            title=f"POST form missing CSRF protection",
            description=(
                f"The POST form (action: {action_url}) does not include a CSRF "
                f"token and session cookies lack the SameSite attribute. An "
                f"attacker could craft a malicious page that submits this form "
                f"on behalf of an authenticated user, performing unwanted "
                f"state-changing actions."
            ),
            evidence={
                "url": action_url,
                "payload": "N/A",
                "response_snippet": self._form_summary(form),
            },
            remediation=self.get_remediation_with_code("csrf",
                "1. Add a hidden CSRF token to every state-changing form and "
                "validate it server-side on every POST request.\n"
                "2. Use your framework's built-in CSRF protection:\n"
                "   - Django: {% csrf_token %} in templates\n"
                "   - Rails: authenticity_token (enabled by default)\n"
                "   - Laravel: @csrf directive in Blade templates\n"
                "   - Express: csurf middleware\n"
                "3. Set SameSite=Lax on session cookies as defense-in-depth.\n"
                "4. Consider using the Double Submit Cookie pattern for APIs."),
            owasp_category="A01:2021 - Broken Access Control",
            cvss_score=8.0,
            affected_url=action_url,
        )

    # ------------------------------------------------------------------
    # GET form state-change heuristic
    # ------------------------------------------------------------------

    def _check_get_form_state_change(self, form: dict) -> None:
        """Flag GET forms whose action or input names suggest they perform
        state changes (delete, update, etc.)."""
        action_url = form["action"]
        suspicious_keywords = ("delete", "remove", "update", "edit", "create", "add", "transfer", "send")

        action_lower = action_url.lower()
        input_names = [inp["name"].lower() for inp in form["inputs"] if inp.get("name")]

        is_suspicious = any(kw in action_lower for kw in suspicious_keywords) or any(
            any(kw in name for kw in suspicious_keywords) for name in input_names
        )

        if is_suspicious:
            self.add_finding(
                severity="medium",
                title=f"GET form may perform state-changing action",
                description=(
                    f"The form at {action_url} uses HTTP GET but its action URL "
                    f"or input names suggest it performs a state-changing operation "
                    f"(delete, update, etc.). GET requests should be idempotent. "
                    f"Using GET for state changes can lead to CSRF via simple link "
                    f"clicks and is cached/logged by proxies."
                ),
                evidence={
                    "url": action_url,
                    "payload": "N/A",
                    "response_snippet": self._form_summary(form),
                },
                remediation=(
                    "1. Change the form method to POST for state-changing operations.\n"
                    "2. Add CSRF token protection to the form.\n"
                    "3. GET requests should only retrieve data, never modify state."
                ),
                owasp_category="A04:2021 - Insecure Design",
                cvss_score=5.4,
                affected_url=action_url,
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _form_summary(form: dict) -> str:
        """Return a concise text summary of a form for evidence."""
        inputs_desc = ", ".join(
            f"{inp['name']} ({inp['type']})" for inp in form["inputs"] if inp.get("name")
        ) or "(no named inputs)"
        return (
            f"Form method={form['method']} action={form['action']} | "
            f"Inputs: {inputs_desc}"
        )
