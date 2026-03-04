"""
HackerPA Engine - Web Crawler / Spider

Central crawler that runs BEFORE all other scanners to discover the full
attack surface of a target website.  It recursively follows same-domain
links (up to a configurable depth and page cap) and collects:

  - All unique page URLs
  - All HTML forms with their actions, methods, and input fields
  - All URL parameters found in links
  - All JavaScript file URLs (linked via <script src>)
  - API-like endpoints referenced inside JavaScript source code

Results are persisted as ``crawlData`` on the Firestore scan document so
that every subsequent scanner can consume them via
``self.crawl_data`` (loaded automatically by BaseScanner.__init__).
"""

import logging
import re
from collections import deque
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urldefrag

from bs4 import BeautifulSoup

from engine.orchestrator import firebase_client
from engine.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

MAX_DEPTH: int = 3
MAX_PAGES: int = 100

# Regex patterns to extract API-like endpoints from JavaScript source code.
# Covers fetch(), axios, XMLHttpRequest.open, and plain string URL literals.
_JS_API_PATTERNS: list[re.Pattern] = [
    # fetch("/api/...") or fetch('/api/...')
    re.compile(r"""fetch\(\s*["'](/[^\s"']+)["']""", re.IGNORECASE),
    # axios.get/post/put/delete/patch("/api/...")
    re.compile(
        r"""axios\.(?:get|post|put|delete|patch)\(\s*["'](/[^\s"']+)["']""",
        re.IGNORECASE,
    ),
    # XMLHttpRequest .open("METHOD", "/api/...")
    re.compile(
        r"""\.open\(\s*["'][A-Z]+["']\s*,\s*["'](/[^\s"']+)["']""",
        re.IGNORECASE,
    ),
    # Generic URL-like strings starting with /api/ or /v1/ etc.
    re.compile(r"""["'](\/(?:api|v[0-9]+)\/[^\s"'?#]+)["']"""),
    # Full http(s) API URLs
    re.compile(r"""["'](https?://[^\s"']+/api/[^\s"'?#]*)["']""", re.IGNORECASE),
]

# File extensions that should NOT be followed (binary / non-HTML assets).
_SKIP_EXTENSIONS: set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".bmp", ".tiff", ".pdf", ".zip", ".gz", ".tar", ".rar",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".exe", ".dll", ".bin", ".dmg", ".iso",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".css",  # We parse JS, but not CSS
}


class CrawlerScanner(BaseScanner):
    """Central web crawler that discovers the full attack surface.

    Must run **before** all other scanners so that ``crawlData`` is
    available on the Firestore scan document.
    """

    scanner_name = "crawler"

    def __init__(self, scan_id: str, project_id: str, domain: str, **kwargs) -> None:
        super().__init__(scan_id, project_id, domain, **kwargs)

        # Parsed origin used for same-domain filtering
        parsed = urlparse(self.base_url)
        self._origin_scheme: str = parsed.scheme
        self._origin_netloc: str = parsed.netloc.lower()

        # Discovered data
        self._visited: set[str] = set()
        self._pages: list[str] = []
        self._forms: list[dict] = []
        self._params: list[dict] = []
        self._js_files: list[str] = []
        self._api_endpoints: list[str] = []

        # De-duplication helpers
        self._seen_js: set[str] = set()
        self._seen_api: set[str] = set()
        self._seen_params: set[str] = set()  # keyed by "url|sorted_params"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        self.log("info", f"Starting crawl of {self.base_url} (max_depth={MAX_DEPTH}, max_pages={MAX_PAGES})")

        self._crawl()

        # Persist crawl data to Firestore
        crawl_data = {
            "pages": self._pages,
            "forms": self._forms,
            "params": self._params,
            "jsFiles": self._js_files,
            "apiEndpoints": self._api_endpoints,
        }

        try:
            if self._data_store:
                self._data_store.save_crawl_data(self.scan_id, crawl_data)
            else:
                firebase_client.update_scan_status(
                    self.scan_id,
                    "running",
                    extra_fields={"crawlData": crawl_data},
                )
        except Exception:
            self.log("error", "Failed to persist crawlData")

        # Log summary
        self.log("info", (
            f"Crawl complete: {len(self._pages)} page(s), "
            f"{len(self._forms)} form(s), "
            f"{len(self._params)} param set(s), "
            f"{len(self._js_files)} JS file(s), "
            f"{len(self._api_endpoints)} API endpoint(s)"
        ))

        # Add an informational finding summarising what was discovered
        self.add_finding(
            severity="info",
            title="Superficie de ataque mapeada pelo crawler",
            description=(
                f"O crawler descobriu {len(self._pages)} pagina(s), "
                f"{len(self._forms)} formulario(s), "
                f"{len(self._params)} conjunto(s) de parametros URL, "
                f"{len(self._js_files)} arquivo(s) JavaScript e "
                f"{len(self._api_endpoints)} endpoint(s) de API."
            ),
            evidence={
                "url": self.base_url,
                "response_snippet": (
                    f"Pages: {len(self._pages)}, Forms: {len(self._forms)}, "
                    f"Params: {len(self._params)}, JS Files: {len(self._js_files)}, "
                    f"API Endpoints: {len(self._api_endpoints)}"
                ),
            },
            remediation=(
                "Revise todos os endpoints e formularios descobertos. "
                "Remova paginas e APIs que nao devem ser publicas."
            ),
            owasp_category="A01:2021 - Broken Access Control",
            affected_url=self.base_url,
        )

    # ------------------------------------------------------------------
    # Core BFS crawl
    # ------------------------------------------------------------------

    def _crawl(self) -> None:
        """Breadth-first crawl starting from ``self.base_url``."""
        # Queue entries are (url, depth)
        queue: deque[tuple[str, int]] = deque()
        queue.append((self._normalise_url(self.base_url), 0))

        while queue and len(self._visited) < MAX_PAGES:
            url, depth = queue.popleft()

            if url in self._visited:
                continue
            if depth > MAX_DEPTH:
                continue

            self._visited.add(url)

            response = self.make_request(url)
            if response is None:
                continue

            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                # Not an HTML page - skip parsing but record if it was reachable
                continue

            self._pages.append(url)
            self.log("info", f"Crawled ({depth}/{MAX_DEPTH}): {url}")

            # Parse the page
            try:
                soup = BeautifulSoup(response.text, "html.parser")
            except Exception:
                self.log("warning", f"Failed to parse HTML at {url}")
                continue

            # Extract data from this page
            self._extract_forms(soup, url)
            self._extract_js_files(soup, url)

            # Discover links to follow
            if depth < MAX_DEPTH:
                for link_url in self._extract_links(soup, url):
                    if link_url not in self._visited:
                        queue.append((link_url, depth + 1))

        # After crawl, fetch JS files and mine them for API endpoints
        self._analyse_js_files()

    # ------------------------------------------------------------------
    # Link extraction and filtering
    # ------------------------------------------------------------------

    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        """Return a list of same-domain, de-fragmented, normalised URLs
        found in ``<a href>`` tags on the page."""
        links: list[str] = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                continue

            absolute = urljoin(page_url, href)
            defragged, _ = urldefrag(absolute)
            normalised = self._normalise_url(defragged)

            if not self._is_same_domain(normalised):
                continue
            if self._has_skip_extension(normalised):
                continue

            # Record URL parameters if present
            self._record_params(normalised)

            links.append(normalised)

        return links

    def _is_same_domain(self, url: str) -> bool:
        """Return True if *url* belongs to the same domain as the target."""
        parsed = urlparse(url)
        return parsed.netloc.lower() == self._origin_netloc

    @staticmethod
    def _has_skip_extension(url: str) -> bool:
        """Return True if the URL path ends with a non-HTML extension."""
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in _SKIP_EXTENSIONS)

    def _normalise_url(self, url: str) -> str:
        """Strip fragments and trailing slashes for consistent de-duplication,
        while preserving query strings."""
        defragged, _ = urldefrag(url)
        parsed = urlparse(defragged)
        # Rebuild without fragment, normalise empty path to /
        path = parsed.path or "/"
        normalised = parsed._replace(fragment="", path=path).geturl()
        return normalised

    # ------------------------------------------------------------------
    # Form extraction
    # ------------------------------------------------------------------

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> None:
        """Find all ``<form>`` elements on the page and record them."""
        for form_tag in soup.find_all("form"):
            try:
                action_raw = form_tag.get("action", "").strip()
                method = (form_tag.get("method", "GET") or "GET").upper()

                if not action_raw:
                    action_url = page_url
                elif action_raw.startswith(("http://", "https://")):
                    action_url = action_raw
                else:
                    action_url = urljoin(page_url, action_raw)

                inputs: list[dict] = []
                for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                    name = input_tag.get("name", "").strip()
                    if not name:
                        continue
                    input_type = (input_tag.get("type", "text") or "text").lower()
                    inputs.append({"name": name, "type": input_type})

                self._forms.append({
                    "url": page_url,
                    "method": method,
                    "action": action_url,
                    "inputs": inputs,
                })
            except Exception:
                self.log("warning", f"Error parsing a <form> on {page_url}")

    # ------------------------------------------------------------------
    # JavaScript file discovery
    # ------------------------------------------------------------------

    def _extract_js_files(self, soup: BeautifulSoup, page_url: str) -> None:
        """Collect all external JavaScript file URLs from ``<script src>``."""
        for script_tag in soup.find_all("script", src=True):
            src = script_tag["src"].strip()
            if not src:
                continue
            absolute = urljoin(page_url, src)
            if absolute not in self._seen_js:
                self._seen_js.add(absolute)
                self._js_files.append(absolute)

    # ------------------------------------------------------------------
    # URL parameter recording
    # ------------------------------------------------------------------

    def _record_params(self, url: str) -> None:
        """If the URL contains query parameters, record them."""
        parsed = urlparse(url)
        if not parsed.query:
            return

        try:
            qs = parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return

        param_names = sorted(qs.keys())
        if not param_names:
            return

        # De-duplicate by base URL + sorted param names
        base_url = parsed._replace(query="", fragment="").geturl()
        dedup_key = f"{base_url}|{'|'.join(param_names)}"
        if dedup_key in self._seen_params:
            return
        self._seen_params.add(dedup_key)

        self._params.append({
            "url": url,
            "params": param_names,
        })

    # ------------------------------------------------------------------
    # JavaScript analysis for API endpoints
    # ------------------------------------------------------------------

    def _analyse_js_files(self) -> None:
        """Fetch each discovered JS file and search for API endpoint patterns."""
        self.log("info", f"Analysing {len(self._js_files)} JavaScript file(s) for API endpoints")

        for js_url in self._js_files:
            try:
                response = self.make_request(js_url)
                if response is None:
                    continue
                # Only process text-like responses
                content_type = response.headers.get("Content-Type", "")
                if "javascript" not in content_type and "text/" not in content_type and "json" not in content_type:
                    continue
                self._mine_api_endpoints(response.text, js_url)
            except Exception:
                self.log("warning", f"Error analysing JS file: {js_url}")

    def _mine_api_endpoints(self, js_source: str, source_url: str) -> None:
        """Apply regex patterns to JavaScript source code to find API
        endpoint references."""
        for pattern in _JS_API_PATTERNS:
            for match in pattern.finditer(js_source):
                endpoint = match.group(1)
                # Resolve relative endpoints to absolute URLs
                if endpoint.startswith("/"):
                    endpoint = urljoin(self.base_url, endpoint)
                if endpoint not in self._seen_api:
                    self._seen_api.add(endpoint)
                    self._api_endpoints.append(endpoint)
                    self.log("info", f"API endpoint found in {source_url}: {endpoint}")
