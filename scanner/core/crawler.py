"""Web crawler for vulnerability scanning."""
from __future__ import annotations
from typing import Dict, List, Set, Optional
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup, Comment

class WebCrawler:
    def __init__(self, base_url: str, max_depth: int = 3, timeout: int = 10, session: requests.Session = None) -> None:
        self.base_url = base_url.rstrip("/")
        parsed = urlparse(self.base_url)
        self.base_netloc = parsed.netloc
        self.base_scheme = parsed.scheme
        self.max_depth = max_depth
        self.timeout = timeout
        self.visited: Set[str] = set()
        self.results: Dict[str, List] = {"urls": [], "forms": []}
        
        # USE SHARED SESSION IF PROVIDED, ELSE CREATE NEW
        self.session = session if session else requests.Session()
        
        # Ensure User-Agent is set
        if "User-Agent" not in self.session.headers:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def crawl(self) -> Dict[str, List]:
        """Start crawling from the base URL and return discovered data."""
        self._check_robots_txt()
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
        except Exception:
            pass

    def _crawl(self, url: str, depth: int) -> None:
        if depth > self.max_depth: return
        if url in self.visited: return

        print(f"Crawling: {url}")
        self.visited.add(url)
        if url not in self.results["urls"]:
            self.results["urls"].append(url)

        try:
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException:
            return

        content_type = resp.headers.get("Content-Type", "").lower()
        if "html" not in content_type: return

        soup = BeautifulSoup(resp.text, "html.parser")
        
        # Extract forms
        forms = self._extract_forms(soup, url)
        if forms: self.results["forms"].extend(forms)

        # Extract links (Deep Scan)
        links = self._extract_all_links(soup, url)
        for link in links:
            if link not in self.visited and self._is_valid_url(link):
                self._crawl(link, depth + 1)

    def _extract_all_links(self, soup: BeautifulSoup, current_url: str) -> List[str]:
        links: Set[str] = set()
        for tag in soup.find_all("a", href=True): links.add(tag["href"])
        for tag in soup.find_all("script", src=True): links.add(tag["src"])
        for tag in soup.find_all("link", href=True): links.add(tag["href"])
        
        # Extract from comments
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            if "/" in comment:
                for p in comment.split():
                    if p.startswith("/") or p.startswith("http"):
                        links.add(p.strip('"\''))

        normalized = []
        for raw in links:
            raw = raw.strip()
            if raw.startswith(("javascript:", "mailto:")): continue
            absolute = urljoin(current_url, raw.split("#")[0])
            normalized.append(absolute.rstrip("/"))
        return normalized

    def _extract_forms(self, soup: BeautifulSoup, current_url: str) -> List[Dict]:
        result = []
        for form in soup.find_all("form"):
            action = urljoin(current_url, form.get("action") or "")
            method = (form.get("method") or "GET").upper()
            inputs = [{"name": i.get("name",""), "type": i.get("type","text")} for i in form.find_all("input")]
            result.append({"action": action, "method": method, "inputs": inputs})
        return result

    def _is_valid_url(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc == self.base_netloc and parsed.scheme in ("http", "https")
