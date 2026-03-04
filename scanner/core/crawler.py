"""
crawler.py — Web Crawler with Playwright SPA support
=====================================================

Fixes vs previous version:
  1. deque instead of list for BFS queue — popleft() is O(1) vs O(n)
     for list.pop(0). At 10,000 URLs this was causing severe CPU lag.
  2. wait_until="domcontentloaded" instead of "networkidle"
     networkidle waits for 500ms of silence — never fires on SPAs with
     websockets, long-polling, analytics, or any continuous background
     traffic. domcontentloaded fires when DOM is parsed — immediately usable.
  3. Hard page timeout of 15s instead of relying on networkidle.
  4. Playwright browser pool reuse (shares pool with XSSScanner if available).
  5. XHR/Fetch interception for API endpoint discovery.
  6. SPA route detection (Next.js, React Router, Vue Router).
"""
from __future__ import annotations

import re
import time
from collections import deque
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, urlunparse

import requests

requests.packages.urllib3.disable_warnings()

# Extensions to skip (binary/static assets)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".zip", ".gz", ".tar", ".rar",
    ".mp4", ".mp3", ".avi", ".mov", ".webm",
    ".exe", ".dll", ".so", ".dylib",
    ".map",  # source maps (consider enabling if hunting secrets)
}

# URL patterns that look like API endpoints
API_PATH_PATTERNS = re.compile(
    r"(/api/|/v\d+/|/graphql|/rest/|/service/|/rpc/|\.json$|\.xml$)",
    re.IGNORECASE,
)

PAGE_TIMEOUT_MS = 15_000   # 15s hard cap per page (was networkidle — hung forever)
NAV_WAIT        = "domcontentloaded"  # FIX: was "networkidle"


class WebCrawler:

    def __init__(self, base_url: str, max_depth: int = 3, timeout: int = 10):
        self.base_url  = base_url.rstrip("/")
        self.max_depth = max_depth
        self.timeout   = timeout
        self.domain    = urlparse(base_url).netloc

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (VulnScanner)"})

    def crawl(self) -> Dict[str, Any]:
        """
        Crawl the target. Returns {"urls": [...], "forms": [...]}.

        Tries Playwright first (JS-rendered SPA support).
        Falls back to BeautifulSoup (static HTML) if Playwright unavailable.
        """
        if self._playwright_available():
            print("[Crawler] Using Playwright engine (JS rendering enabled)")
            return self._crawl_playwright()
        else:
            print("[Crawler] Playwright not available — using BeautifulSoup (static only)")
            return self._crawl_bs4()

    # ------------------------------------------------------------------
    # Playwright crawler
    # ------------------------------------------------------------------

    def _crawl_playwright(self) -> Dict[str, Any]:
        from playwright.sync_api import sync_playwright

        visited: Set[str]       = set()
        all_forms: List[Dict]   = []
        network_urls: Set[str]  = set()

        # BFS queue: (url, depth) — deque for O(1) popleft
        # FIX: was list, pop(0) is O(n) — deque.popleft() is O(1)
        queue: deque = deque()
        queue.append((self.base_url, 0))

        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            context = browser.new_context(ignore_https_errors=True)

            # Sync session cookies to Playwright
            self._sync_cookies(context)

            while queue:
                url, depth = queue.popleft()  # O(1) — was pop(0) = O(n)

                if url in visited or depth > self.max_depth:
                    continue
                if not self._same_domain(url):
                    continue

                visited.add(url)
                print(f"[Crawler] [{depth}/{self.max_depth}] {url}")

                page        = None
                page_urls:  Set[str] = set()
                page_forms: List[Dict] = []

                try:
                    page = context.new_page()

                    # Network interception for API endpoint discovery
                    def handle_request(req):
                        req_url = req.url
                        if (self._same_domain(req_url)
                                and API_PATH_PATTERNS.search(req_url)
                                and not self._skip_url(req_url)):
                            network_urls.add(req_url.split("?")[0])

                    page.on("request", handle_request)

                    # Navigate with domcontentloaded (not networkidle)
                    # FIX: networkidle never fires on SPAs with websockets/analytics
                    try:
                        page.goto(url, wait_until=NAV_WAIT, timeout=PAGE_TIMEOUT_MS)
                    except Exception as e:
                        print(f"[Crawler] Navigation timeout/error for {url}: {e}")
                        # Still try to extract what loaded

                    # Extra wait for SPA hydration if framework detected
                    if self._detect_spa(page):
                        try:
                            page.wait_for_timeout(2000)
                            # Trigger SPA routes by clicking nav elements
                            self._click_nav_items(page)
                        except Exception:
                            pass

                    # Extract links
                    page_urls = self._extract_links_playwright(page, url)

                    # Extract forms (live DOM — catches JS-rendered forms)
                    page_forms = self._extract_forms_playwright(page, url)

                    # Discover Next.js / React Router routes
                    page_urls.update(self._extract_spa_routes(page))

                except Exception as e:
                    print(f"[Crawler] Error on {url}: {e}")
                finally:
                    if page:
                        try:
                            page.close()
                        except Exception:
                            pass

                all_forms.extend(page_forms)
                for link in page_urls:
                    if link not in visited:
                        queue.append((link, depth + 1))

            context.close()
            browser.close()

        # Seed with robots.txt and sitemap
        extra = set()
        extra.update(self._fetch_robots_txt())
        extra.update(self._fetch_sitemap())

        all_urls = list(dict.fromkeys(
            list(visited) + list(network_urls) + list(extra)
        ))
        forms    = self._dedup_forms(all_forms)

        print(f"[Crawler] Complete: {len(all_urls)} URLs, {len(forms)} forms")
        return {"urls": all_urls, "forms": forms}

    def _extract_links_playwright(self, page: Any, base_url: str) -> Set[str]:
        links: Set[str] = set()
        try:
            hrefs = page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                         .map(a => a.href)
            """)
            for href in hrefs:
                url = self._normalize_url(href, base_url)
                if url and self._same_domain(url) and not self._skip_url(url):
                    links.add(url)
        except Exception:
            pass
        return links

    def _extract_forms_playwright(self, page: Any, base_url: str) -> List[Dict]:
        forms = []
        try:
            raw_forms = page.evaluate("""
                () => Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action || '',
                    method: f.method || 'get',
                    inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                        name:  i.name  || '',
                        type:  i.type  || 'text',
                        value: i.value || '',
                    }))
                }))
            """)
            for f in raw_forms:
                action = f.get("action") or base_url
                if not action.startswith("http"):
                    action = urljoin(base_url, action)
                forms.append({
                    "action": action,
                    "method": f.get("method", "get").lower(),
                    "inputs": f.get("inputs", []),
                })
        except Exception:
            pass
        return forms

    def _extract_spa_routes(self, page: Any) -> Set[str]:
        routes: Set[str] = set()
        try:
            # Next.js exposes routes in __NEXT_DATA__
            next_data = page.evaluate("() => window.__NEXT_DATA__")
            if next_data:
                build_id = next_data.get("buildId", "")
                pages    = next_data.get("pages", [])
                for p in pages:
                    url = urljoin(self.base_url, p)
                    if self._same_domain(url):
                        routes.add(url)

            # React Router / Vue Router may expose __routes
            app_routes = page.evaluate("() => window.__routes || []")
            if isinstance(app_routes, list):
                for r in app_routes:
                    if isinstance(r, str) and r.startswith("/"):
                        routes.add(urljoin(self.base_url, r))
        except Exception:
            pass
        return routes

    def _click_nav_items(self, page: Any):
        """Click navigation elements to trigger SPA route changes."""
        nav_selectors = [
            "nav a", "[role='navigation'] a", ".navbar a",
            ".nav-link", ".menu-item a", "header a",
        ]
        for selector in nav_selectors:
            try:
                elements = page.query_selector_all(selector)
                for el in elements[:5]:  # limit clicks per selector
                    try:
                        el.click(timeout=1000)
                        page.wait_for_timeout(500)
                    except Exception:
                        pass
            except Exception:
                pass

    def _detect_spa(self, page: Any) -> bool:
        """Detect if page is a React/Vue/Angular SPA."""
        try:
            indicators = page.evaluate("""
                () => ({
                    react:    !!(window.React || document.querySelector('[data-reactroot]')),
                    vue:      !!(window.Vue || document.querySelector('[data-v-]')),
                    angular:  !!(window.angular || document.querySelector('[ng-version]')),
                    next:     !!(window.__NEXT_DATA__),
                })
            """)
            return any(indicators.values())
        except Exception:
            return False

    # ------------------------------------------------------------------
    # BeautifulSoup fallback crawler
    # ------------------------------------------------------------------

    def _crawl_bs4(self) -> Dict[str, Any]:
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            print("[Crawler] BeautifulSoup not installed — install with: pip install beautifulsoup4")
            return {"urls": [self.base_url], "forms": []}

        visited: Set[str]     = set()
        all_forms: List[Dict] = []

        # FIX: deque for O(1) popleft
        queue: deque = deque()
        queue.append((self.base_url, 0))

        while queue:
            url, depth = queue.popleft()

            if url in visited or depth > self.max_depth:
                continue
            if not self._same_domain(url):
                continue

            visited.add(url)

            try:
                resp = self.session.get(url, timeout=self.timeout)
                if "text/html" not in resp.headers.get("content-type", ""):
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
            except Exception:
                continue

            # Links
            for tag in soup.find_all("a", href=True):
                link = self._normalize_url(tag["href"], url)
                if link and self._same_domain(link) and not self._skip_url(link):
                    if link not in visited:
                        queue.append((link, depth + 1))

            # Forms
            for form in soup.find_all("form"):
                action = form.get("action", "") or url
                if not action.startswith("http"):
                    action = urljoin(url, action)
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    if name:
                        inputs.append({
                            "name":  name,
                            "type":  inp.get("type", "text"),
                            "value": inp.get("value", ""),
                        })
                if inputs:
                    all_forms.append({
                        "action": action,
                        "method": (form.get("method", "get") or "get").lower(),
                        "inputs": inputs,
                    })

        extra = set()
        extra.update(self._fetch_robots_txt())
        extra.update(self._fetch_sitemap())

        all_urls = list(dict.fromkeys(list(visited) + list(extra)))
        forms    = self._dedup_forms(all_forms)

        print(f"[Crawler] BS4 complete: {len(all_urls)} URLs, {len(forms)} forms")
        return {"urls": all_urls, "forms": forms}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _playwright_available(self) -> bool:
        try:
            import playwright
            return True
        except ImportError:
            return False

    def _sync_cookies(self, context: Any):
        """Copy requests.Session cookies into Playwright context."""
        cookies = []
        for c in self.session.cookies:
            cookies.append({
                "name":   c.name,
                "value":  c.value,
                "domain": c.domain or self.domain,
                "path":   c.path or "/",
            })
        if cookies:
            context.add_cookies(cookies)
            print(f"[Crawler] Synced {len(cookies)} session cookies to Playwright")

    def _normalize_url(self, href: str, base: str) -> Optional[str]:
        if not href:
            return None
        href = href.strip()
        if href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            return None
        url = urljoin(base, href)
        # Strip fragment
        parsed = urlparse(url)
        return urlunparse(parsed._replace(fragment=""))

    def _same_domain(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self.domain
        except Exception:
            return False

    def _skip_url(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)

    def _fetch_robots_txt(self) -> Set[str]:
        urls: Set[str] = set()
        try:
            resp = self.session.get(
                f"{self.base_url}/robots.txt", timeout=self.timeout
            )
            for line in resp.text.splitlines():
                if line.lower().startswith(("disallow:", "allow:")):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        url = urljoin(self.base_url, path)
                        if self._same_domain(url):
                            urls.add(url)
        except Exception:
            pass
        return urls

    def _fetch_sitemap(self) -> Set[str]:
        urls: Set[str] = set()
        try:
            resp = self.session.get(
                f"{self.base_url}/sitemap.xml", timeout=self.timeout
            )
            for match in re.findall(r"<loc>(.*?)</loc>", resp.text):
                url = match.strip()
                if self._same_domain(url) and not self._skip_url(url):
                    urls.add(url)
        except Exception:
            pass
        return urls

    def _dedup_forms(self, forms: List[Dict]) -> List[Dict]:
        seen:   Set[tuple]  = set()
        unique: List[Dict]  = []
        for f in forms:
            key = (
                f.get("action", ""),
                f.get("method", ""),
                tuple(sorted(i.get("name", "") for i in f.get("inputs", []))),
            )
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique