"""Web crawler for vulnerability scanning.

Provides a depth-limited crawler that discovers URLs, HTML forms, 
and hidden assets (JS/CSS/Robots) within the same domain.
"""
from __future__ import annotations

from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Comment


class WebCrawler:
    """Depth-limited web crawler for vulnerability scanning.

    Args:
        base_url: The starting URL to crawl.
        max_depth: Maximum recursion depth.
        timeout: Timeout (seconds) for HTTP requests.
    """

    def __init__(self, base_url: str, max_depth: int = 3, timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        parsed = urlparse(self.base_url)
        self.base_netloc = parsed.netloc
        self.base_scheme = parsed.scheme
        self.max_depth = max_depth
        self.timeout = timeout
        self.visited: Set[str] = set()
        self.results: Dict[str, List] = {"urls": [], "forms": []}
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def crawl(self) -> Dict[str, List]:
        """Start crawling from the base URL and return discovered data."""
        # 1. Always check robots.txt first (CTF Goldmine)
        self._check_robots_txt()
        
        # 2. Start normal crawling
        self._crawl(self.base_url, 0)
        return self.results

    def _check_robots_txt(self):
        """Explicitly check for robots.txt."""
        robots_url = f"{self.base_scheme}://{self.base_netloc}/robots.txt"
        print(f"Checking: {robots_url}")
        try:
            resp = self.session.get(robots_url, timeout=self.timeout)
            if resp.status_code == 200:
                self.results["urls"].append(robots_url)
                # We don't parse robots.txt for links in this simple version, 
                # but adding it allows FlagHunter to scan its content.
        except Exception:
            pass

    def _crawl(self, url: str, depth: int) -> None:
        if depth > self.max_depth:
            return

        if url in self.visited:
            return

        print(f"Crawling: {url}")
        self.visited.add(url)
        # Record the URL so FlagHunter scans it later
        if url not in self.results["urls"]:
            self.results["urls"].append(url)

        try:
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            print(f"Failed to fetch {url}: {exc}")
            return

        # Only parse HTML for further links
        content_type = resp.headers.get("Content-Type", "").lower()
        if "html" not in content_type:
            return

        soup = BeautifulSoup(resp.text, "html.parser")

        # Extract and record forms
        forms = self._extract_forms(soup, url)
        if forms:
            self.results["forms"].extend(forms)

        # Extract links (Deep Scan: a, script, link, comments)
        links = self._extract_all_links(soup, url)
        for link in links:
            if link not in self.visited and self._is_valid_url(link):
                self._crawl(link, depth + 1)

    def _extract_all_links(self, soup: BeautifulSoup, current_url: str) -> List[str]:
        """Extract hrefs/srcs from a, script, link tags and comments."""
        links: Set[str] = set() # Use set to avoid duplicates
        
        # 1. Standard Links <a href>
        for tag in soup.find_all("a", href=True):
            links.add(tag["href"])
            
        # 2. Scripts <script src> (Often contain flags or API endpoints)
        for tag in soup.find_all("script", src=True):
            links.add(tag["src"])
            
        # 3. Stylesheets <link href>
        for tag in soup.find_all("link", href=True):
            links.add(tag["href"])
            
        # 4. Comments (Developers often leave backup file paths here)
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            # Very basic extraction: look for strings starting with / or http
            if "/" in comment:
                parts = comment.split()
                for p in parts:
                    if p.startswith("/") or p.startswith("http"):
                        links.add(p.strip('"\''))

        # Normalize all found links
        normalized_links = []
        for raw_link in links:
            raw_link = raw_link.strip()
            if raw_link.startswith(("javascript:", "mailto:")):
                continue
            
            absolute = urljoin(current_url, raw_link.split("#")[0])
            normalized_links.append(absolute.rstrip("/"))
            
        return normalized_links

    def _extract_forms(self, soup: BeautifulSoup, current_url: str) -> List[Dict]:
        """Extract forms with action, method, and input fields."""
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
            for ta in form.find_all("textarea"):
                inputs.append({"name": ta.get("name", ""), "type": "textarea"})
            for sel in form.find_all("select"):
                inputs.append({"name": sel.get("name", ""), "type": "select"})

            result.append({"action": action_url, "method": method, "inputs": inputs})
        return result

    def _is_valid_url(self, url: str) -> bool:
        """Return True if the URL should be crawled (same domain)."""
        parsed = urlparse(url)
        return parsed.netloc == self.base_netloc and parsed.scheme in ("http", "https")
