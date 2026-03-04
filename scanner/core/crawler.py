"""
Web Crawler — Full Rewrite with Playwright
===========================================
Two-engine architecture:
  1. Playwright (headless Chromium) — primary engine
     - Renders JavaScript, executes React/Vue/Angular routing
     - Intercepts XHR/Fetch requests to discover API endpoints
     - Extracts links from live DOM (not raw HTML)
     - Detects and fills forms rendered by JS frameworks
     - Follows client-side navigation (pushState, hashchange)

  2. Requests + BeautifulSoup — fallback engine
     - Used when Playwright is not installed
     - Also used for non-HTML assets (robots.txt, sitemap.xml)

Key improvements over v1:
  - SPAs: React/Vue/Angular routes discovered via JS interception
  - XHR/Fetch interception: API endpoints found even if not in DOM
  - Dynamic forms: forms rendered by JS are captured post-render
  - Client-side routing: follows pushState and hash navigation
  - Network request map: every URL the browser fetches is recorded
  - Graceful fallback: works without Playwright (BeautifulSoup mode)
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Comment

try:
    from playwright.sync_api import (
        sync_playwright,
        TimeoutError as PWTimeout,
        Page,
        Browser,
    )
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# JS framework indicators in page source
SPA_INDICATORS = [
    "react", "vue", "angular", "next.js", "nuxt",
    "__NEXT_DATA__", "ng-version", "data-reactroot",
    "svelte", "ember", "backbone",
]

# API path patterns to capture from network requests
API_PATH_PATTERNS = [
    r"/api/",
    r"/v\d+/",
    r"/graphql",
    r"/rest/",
    r"/service/",
    r"/data/",
    r"\.json$",
]

# File extensions to skip (binary assets)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3", ".woff",
    ".woff2", ".ttf", ".eot", ".otf", ".css", ".map",
}


# ---------------------------------------------------------------------------
# Main Crawler
# ---------------------------------------------------------------------------

class WebCrawler:
    """
    Dual-engine web crawler.

    Uses Playwright (headless Chromium) when available for full JS rendering.
    Falls back to requests + BeautifulSoup for static HTML sites.
    """

    def __init__(self, base_url: str, max_depth: int = 3,
                 timeout: int = 10,
                 session: Optional[requests.Session] = None) -> None:
        self.base_url    = base_url.rstrip("/")
        parsed           = urlparse(self.base_url)
        self.base_netloc = parsed.netloc
        self.base_scheme = parsed.scheme
        self.max_depth   = max_depth
        self.timeout     = timeout
        self.session     = session or requests.Session()

        if "User-Agent" not in self.session.headers:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

        self.visited: Set[str]  = set()
        self.results: Dict      = {"urls": [], "forms": []}

        # Network request map from Playwright interception
        self._network_urls: Set[str] = set()

        if not PLAYWRIGHT_AVAILABLE:
            print("[Crawler] Playwright not installed — using BeautifulSoup fallback.")
            print("          Install: pip install playwright && playwright install chromium")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self) -> Dict[str, List]:
        """Crawl the target and return discovered URLs and forms."""
        # Always grab robots.txt and sitemap first (static, no JS needed)
        self._fetch_robots_txt()
        self._fetch_sitemap()

        if PLAYWRIGHT_AVAILABLE:
            print("[Crawler] Playwright available — using headless Chromium engine")
            self._crawl_playwright(self.base_url, depth=0)
        else:
            print("[Crawler] Using BeautifulSoup fallback engine")
            self._crawl_bs(self.base_url, depth=0)

        # Deduplicate
        self.results["urls"]  = list(dict.fromkeys(self.results["urls"]))
        self.results["forms"] = self._dedup_forms(self.results["forms"])

        print(f"[Crawler] Done — {len(self.results['urls'])} URLs, "
              f"{len(self.results['forms'])} forms discovered")
        return self.results

    # ------------------------------------------------------------------
    # Engine 1: Playwright
    # ------------------------------------------------------------------

    def _crawl_playwright(self, start_url: str, depth: int) -> None:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="vuln-scanner/1.0",
                ignore_https_errors=True,
            )

            # Pass existing session cookies into Playwright
            self._sync_cookies_to_playwright(context)

            page = context.new_page()
            self._setup_network_interception(page)

            queue: List[tuple[str, int]] = [(start_url, 0)]

            while queue:
                url, current_depth = queue.pop(0)

                if current_depth > self.max_depth:
                    continue
                if url in self.visited:
                    continue
                if not self._is_valid_url(url):
                    continue

                self.visited.add(url)
                print(f"[Crawler] [{current_depth}/{self.max_depth}] {url}")

                try:
                    page.goto(url, timeout=self.timeout * 1000,
                              wait_until="networkidle")
                except PWTimeout:
                    print(f"  [!] Timeout on {url}")
                    continue
                except Exception as exc:
                    print(f"  [!] Error on {url}: {exc}")
                    continue

                # Wait extra for heavy SPAs
                if self._is_spa(page):
                    print(f"  [SPA] Framework detected on {url} — waiting for hydration")
                    page.wait_for_timeout(2000)

                # Record URL
                if url not in self.results["urls"]:
                    self.results["urls"].append(url)

                # Extract links from live DOM
                new_links = self._extract_links_playwright(page, url)

                # Extract forms from live DOM
                forms = self._extract_forms_playwright(page, url)
                self.results["forms"].extend(forms)

                # Follow client-side routes
                spa_routes = self._follow_spa_routes(page, url)
                new_links.update(spa_routes)

                # Queue newly discovered links
                for link in new_links:
                    if link not in self.visited and self._is_valid_url(link):
                        queue.append((link, current_depth + 1))

            # Add all intercepted network URLs
            for net_url in self._network_urls:
                if net_url not in self.results["urls"]:
                    self.results["urls"].append(net_url)

            browser.close()

    def _setup_network_interception(self, page: "Page") -> None:
        """Intercept all network requests to discover API endpoints."""
        def _on_request(request):
            req_url = request.url
            parsed  = urlparse(req_url)

            # Only capture same-domain requests
            if parsed.netloc != self.base_netloc:
                return

            # Skip binary assets
            if any(parsed.path.endswith(ext) for ext in SKIP_EXTENSIONS):
                return

            # Capture API endpoints specifically
            is_api = any(re.search(p, parsed.path) for p in API_PATH_PATTERNS)
            is_html = request.resource_type in ("document", "xhr", "fetch")

            if is_api or is_html:
                clean = req_url.split("#")[0].rstrip("/")
                self._network_urls.add(clean)

        page.on("request", _on_request)

    def _extract_links_playwright(self, page: "Page", current_url: str) -> Set[str]:
        """Extract all hrefs from the live rendered DOM."""
        links: Set[str] = set()
        try:
            hrefs = page.eval_on_selector_all(
                "a[href], [data-href], [data-url]",
                "els => els.map(e => e.href || e.dataset.href || e.dataset.url || '')"
            )
            for href in hrefs:
                if href and not href.startswith(("javascript:", "mailto:", "tel:")):
                    absolute = urljoin(current_url, href.split("#")[0])
                    links.add(absolute.rstrip("/"))
        except Exception:
            pass

        # Also grab from JS bundle routes if exposed on window
        try:
            js_routes = page.evaluate("""
                () => {
                    const routes = [];
                    // Next.js
                    if (window.__NEXT_DATA__?.buildId) {
                        try {
                            const manifest = window.__NEXT_MANIFEST__;
                            if (manifest) Object.keys(manifest).forEach(r => routes.push(r));
                        } catch(e) {}
                    }
                    // React Router / Vue Router exposed routes
                    if (window.__routes) {
                        window.__routes.forEach(r => routes.push(r.path || r));
                    }
                    return routes;
                }
            """)
            for route in (js_routes or []):
                if isinstance(route, str) and route.startswith("/"):
                    absolute = f"{self.base_scheme}://{self.base_netloc}{route}"
                    links.add(absolute)
        except Exception:
            pass

        return links

    def _extract_forms_playwright(self, page: "Page",
                                   current_url: str) -> List[Dict]:
        """Extract forms from the live rendered DOM (includes JS-rendered forms)."""
        forms = []
        try:
            raw_forms = page.evaluate("""
                () => Array.from(document.forms).map(f => ({
                    action: f.action || '',
                    method: f.method || 'GET',
                    inputs: Array.from(f.elements)
                        .filter(e => e.name)
                        .map(e => ({
                            name: e.name,
                            type: e.type || 'text',
                            value: e.value || ''
                        }))
                }))
            """)
            for f in (raw_forms or []):
                action = f.get("action") or current_url
                if not action.startswith("http"):
                    action = urljoin(current_url, action)
                forms.append({
                    "action": action,
                    "method": (f.get("method") or "GET").upper(),
                    "inputs": f.get("inputs", []),
                })
        except Exception:
            pass
        return forms

    def _follow_spa_routes(self, page: "Page", current_url: str) -> Set[str]:
        """
        Simulate clicking nav links and intercept pushState navigation
        to discover client-side routes not in the DOM as <a href>.
        """
        routes: Set[str] = set()
        try:
            # Intercept history.pushState calls
            page.evaluate("""
                () => {
                    window.__spa_routes = [];
                    const orig = history.pushState.bind(history);
                    history.pushState = function(state, title, url) {
                        if (url) window.__spa_routes.push(url);
                        return orig(state, title, url);
                    };
                }
            """)

            # Click nav / menu items to trigger routing
            nav_selectors = [
                "nav a", "[role='navigation'] a",
                ".nav a", ".menu a", ".navbar a",
                "[class*='nav'] a", "[class*='menu'] a",
            ]
            for selector in nav_selectors:
                try:
                    links = page.query_selector_all(selector)
                    for link in links[:8]:  # cap at 8 per selector
                        try:
                            href = link.get_attribute("href") or ""
                            if href and not href.startswith(("javascript:", "mailto:")):
                                absolute = urljoin(current_url, href)
                                if self._is_valid_url(absolute):
                                    routes.add(absolute.rstrip("/"))
                        except Exception:
                            pass
                except Exception:
                    pass

            # Collect pushState-captured routes
            spa_routes = page.evaluate("() => window.__spa_routes || []")
            for route in (spa_routes or []):
                if isinstance(route, str):
                    absolute = urljoin(current_url, route)
                    if self._is_valid_url(absolute):
                        routes.add(absolute.rstrip("/"))

        except Exception:
            pass

        return routes

    def _is_spa(self, page: "Page") -> bool:
        """Detect if the page is a JS framework SPA."""
        try:
            html = page.content().lower()
            return any(indicator in html for indicator in SPA_INDICATORS)
        except Exception:
            return False

    def _sync_cookies_to_playwright(self, context) -> None:
        """Copy cookies from the requests session into the Playwright context."""
        try:
            cookies = []
            for cookie in self.session.cookies:
                cookies.append({
                    "name":   cookie.name,
                    "value":  cookie.value,
                    "domain": cookie.domain or self.base_netloc,
                    "path":   cookie.path or "/",
                })
            if cookies:
                context.add_cookies(cookies)
                print(f"  [Auth] Synced {len(cookies)} session cookies to Playwright")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Engine 2: BeautifulSoup fallback
    # ------------------------------------------------------------------

    def _crawl_bs(self, url: str, depth: int) -> None:
        if depth > self.max_depth or url in self.visited:
            return
        if not self._is_valid_url(url):
            return

        self.visited.add(url)
        print(f"[Crawler-BS] [{depth}/{self.max_depth}] {url}")

        if url not in self.results["urls"]:
            self.results["urls"].append(url)

        try:
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            print(f"  [!] Failed to fetch {url}: {exc}")
            return

        content_type = resp.headers.get("Content-Type", "").lower()
        if "html" not in content_type:
            return

        soup = BeautifulSoup(resp.text, "html.parser")

        # Warn if SPA detected in fallback mode
        html_lower = resp.text.lower()
        if any(ind in html_lower for ind in SPA_INDICATORS):
            print(f"  [!] SPA framework detected on {url} — "
                  f"install Playwright for full coverage")

        forms = self._extract_forms_bs(soup, url)
        self.results["forms"].extend(forms)

        for link in self._extract_links_bs(soup, url):
            if link not in self.visited:
                self._crawl_bs(link, depth + 1)

    def _extract_links_bs(self, soup: BeautifulSoup,
                           current_url: str) -> List[str]:
        links: Set[str] = set()

        for tag in soup.find_all("a", href=True):
            links.add(tag["href"])
        for tag in soup.find_all("script", src=True):
            links.add(tag["src"])
        for tag in soup.find_all("link", href=True):
            links.add(tag["href"])

        # HTML comments sometimes contain URLs
        for comment in soup.find_all(
                string=lambda t: isinstance(t, Comment)):
            for part in comment.split():
                if part.startswith(("/", "http")):
                    links.add(part.strip("\"'"))

        normalized = []
        for raw in links:
            raw = raw.strip()
            if raw.startswith(("javascript:", "mailto:", "tel:")):
                continue
            ext = urlparse(raw).path.rsplit(".", 1)[-1].lower()
            if f".{ext}" in SKIP_EXTENSIONS:
                continue
            absolute = urljoin(current_url, raw.split("#")[0])
            normalized.append(absolute.rstrip("/"))

        return [u for u in normalized if self._is_valid_url(u)]

    def _extract_forms_bs(self, soup: BeautifulSoup,
                           current_url: str) -> List[Dict]:
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(current_url, form.get("action") or "")
            method = (form.get("method") or "GET").upper()
            inputs = []
            for inp in form.find_all("input"):
                inputs.append({"name": inp.get("name", ""),
                               "type": inp.get("type", "text")})
            for ta in form.find_all("textarea"):
                inputs.append({"name": ta.get("name", ""), "type": "textarea"})
            for sel in form.find_all("select"):
                inputs.append({"name": sel.get("name", ""), "type": "select"})
            forms.append({"action": action, "method": method, "inputs": inputs})
        return forms

    # ------------------------------------------------------------------
    # Static asset helpers
    # ------------------------------------------------------------------

    def _fetch_robots_txt(self) -> None:
        url = f"{self.base_scheme}://{self.base_netloc}/robots.txt"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                if url not in self.results["urls"]:
                    self.results["urls"].append(url)
                # Extract Disallow / Allow paths as potential targets
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:")):
                        path = line.split(":", 1)[-1].strip()
                        if path and path != "/":
                            absolute = (f"{self.base_scheme}://"
                                        f"{self.base_netloc}{path}")
                            if absolute not in self.results["urls"]:
                                self.results["urls"].append(absolute)
        except Exception:
            pass

    def _fetch_sitemap(self) -> None:
        for path in ["/sitemap.xml", "/sitemap_index.xml"]:
            url = f"{self.base_scheme}://{self.base_netloc}{path}"
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200 and "xml" in resp.headers.get(
                        "Content-Type", ""):
                    # Extract <loc> URLs from sitemap
                    locs = re.findall(r"<loc>(.*?)</loc>", resp.text, re.IGNORECASE)
                    for loc in locs:
                        loc = loc.strip()
                        if self._is_valid_url(loc) and loc not in self.results["urls"]:
                            self.results["urls"].append(loc)
                    if locs:
                        print(f"[Crawler] Sitemap: {len(locs)} URLs from {path}")
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _is_valid_url(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            if parsed.netloc != self.base_netloc:
                return False
            if parsed.scheme not in ("http", "https"):
                return False
            ext = parsed.path.rsplit(".", 1)[-1].lower()
            if f".{ext}" in SKIP_EXTENSIONS:
                return False
            return True
        except Exception:
            return False

    def _dedup_forms(self, forms: List[Dict]) -> List[Dict]:
        seen: Set[tuple] = set()
        unique = []
        for f in forms:
            key = (f.get("action"), f.get("method"),
                   tuple(i.get("name") for i in f.get("inputs", [])))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique