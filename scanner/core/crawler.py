"""Web crawler for vulnerability scanning.

Provides a simple depth-limited crawler that discovers URLs and HTML forms
within the same domain as the provided base URL. Uses `requests` and
`BeautifulSoup` to fetch and parse pages.
"""
from __future__ import annotations

from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class WebCrawler:
    """Depth-limited web crawler for vulnerability scanning.

    Args:
        base_url: The starting URL to crawl. Only URLs with the same domain
            as this URL will be followed.
        max_depth: Maximum recursion depth (root is depth 0).
        timeout: Timeout (seconds) for HTTP requests.
    """

    def __init__(self, base_url: str, max_depth: int = 3, timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        parsed = urlparse(self.base_url)
        self.base_netloc = parsed.netloc
        self.max_depth = max_depth
        self.timeout = timeout
        self.visited: Set[str] = set()
        self.results: Dict[str, List] = {"urls": [], "forms": []}
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def crawl(self) -> Dict[str, List]:
        """Start crawling from the base URL and return discovered data.

        Returns a dict with keys `urls` and `forms`.
        """
        self._crawl(self.base_url, 0)
        return self.results

    def _crawl(self, url: str, depth: int) -> None:
        if depth > self.max_depth:
            return

        if url in self.visited:
            return

        print(f"Crawling: {url}")
        self.visited.add(url)
        self.results["urls"].append(url)

        try:
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            print(f"Failed to fetch {url}: {exc}")
            return

        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type:
            # Skip non-HTML resources
            return

        soup = BeautifulSoup(resp.text, "html.parser")

        # Extract and record forms on the page
        forms = self._extract_forms(soup, url)
        if forms:
            self.results["forms"].extend(forms)

        # Extract links and recurse
        links = self._extract_links(soup, url)
        for link in links:
            if link not in self.visited and self._is_valid_url(link):
                self._crawl(link, depth + 1)

    def _extract_links(self, soup: BeautifulSoup, current_url: str) -> List[str]:
        """Extract and normalize hrefs from <a> tags on the page.

        Returns a list of absolute URLs within the same scheme/domain.
        """
        links: List[str] = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            # Ignore javascript:, mailto:, and fragments
            if href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            # Resolve relative URLs
            absolute = urljoin(current_url, href.split("#")[0])
            parsed = urlparse(absolute)
            if parsed.scheme not in ("http", "https"):
                continue
            links.append(absolute.rstrip("/"))
        return links

    def _extract_forms(self, soup: BeautifulSoup, current_url: str) -> List[Dict]:
        """Extract forms with action, method, and input fields.

        The `action` is returned as an absolute URL resolved against
        the page's URL to make subsequent scanning simpler.
        """
        result: List[Dict] = []
        for form in soup.find_all("form"):
            action = form.get("action") or ""
            action_url = urljoin(current_url, action)
            method = (form.get("method") or "GET").upper()

            inputs: List[Dict] = []
            for inp in form.find_all("input"):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                })
            # Include textareas
            for ta in form.find_all("textarea"):
                inputs.append({"name": ta.get("name", ""), "type": "textarea"})
            # Include selects
            for sel in form.find_all("select"):
                inputs.append({"name": sel.get("name", ""), "type": "select"})

            result.append({"action": action_url, "method": method, "inputs": inputs})
        return result

    def _is_valid_url(self, url: str) -> bool:
        """Return True if the URL should be crawled (same domain as base)."""
        parsed = urlparse(url)
        return parsed.netloc == self.base_netloc and parsed.scheme in ("http", "https")
