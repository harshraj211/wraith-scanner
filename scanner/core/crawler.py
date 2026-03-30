"""
crawler.py — Web Crawler with async Playwright SPA support
==========================================================

Architecture (v3 — async_playwright):
  - async_playwright for all JS-rendered pages (non-blocking I/O)
  - asyncio.run() wraps the async crawl inside the sync crawl() API
  - BFS queue with domcontentloaded (never hangs on SPAs)
  - Full fetch/XHR interception for API endpoint discovery
  - SPA hash route exploration for Angular/Vue apps
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs

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

    def __init__(self, base_url: str, max_depth: int = 3, timeout: int = 10,
                 session: Optional[requests.Session] = None):
        self.base_url  = base_url.rstrip("/")
        self.max_depth = max_depth
        self.timeout   = timeout
        self.domain    = urlparse(base_url).netloc

        self.session = session or requests.Session()
        self.session.verify = False
        if "User-Agent" not in self.session.headers:
            self.session.headers.update({"User-Agent": "Mozilla/5.0 (VulnScanner)"})

    def crawl(self) -> Dict[str, Any]:
        """
        Crawl the target. Returns {"urls": [...], "forms": [...]}.

        Tries async Playwright first (JS-rendered SPA support).
        Falls back to BeautifulSoup (static HTML) if Playwright unavailable.
        """
        if self._playwright_available():
            print("[Crawler] Using async Playwright engine (JS rendering enabled)")
            return asyncio.run(self._crawl_playwright_async())
        else:
            print("[Crawler] Playwright not available — using BeautifulSoup (static only)")
            return self._crawl_bs4()

    # ------------------------------------------------------------------
    # Async Playwright crawler
    # ------------------------------------------------------------------

    async def _crawl_playwright_async(self) -> Dict[str, Any]:
        from playwright.async_api import async_playwright

        visited: Set[str]       = set()
        all_forms: List[Dict]   = []
        network_urls: Set[str]  = set()
        api_requests: List[Dict] = []
        api_seen: Set[str]       = set()

        queue: deque = deque()
        queue.append((self.base_url, 0))

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            )

            await self._sync_cookies_async(context)

            while queue:
                url, depth = queue.popleft()

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
                    page = await context.new_page()

                    def handle_request(req):
                        req_url = req.url
                        if not self._same_domain(req_url):
                            return
                        if self._skip_url(req_url):
                            return
                        base_req_url = req_url.split("?")[0]
                        network_urls.add(base_req_url)
                        res_type = req.resource_type
                        if res_type in ("fetch", "xhr"):
                            dedup_key = f"{req.method} {base_req_url}"
                            if dedup_key not in api_seen:
                                api_seen.add(dedup_key)
                                api_req = {
                                    "url": req_url,
                                    "method": req.method.upper(),
                                    "post_data": None,
                                    "content_type": "",
                                }
                                try:
                                    api_req["post_data"] = req.post_data
                                except Exception:
                                    pass
                                try:
                                    headers = req.headers
                                    api_req["content_type"] = headers.get("content-type", "")
                                except Exception:
                                    pass
                                api_requests.append(api_req)
                                print(f"[Crawler]   API: {req.method} {base_req_url}")

                    page.on("request", handle_request)

                    # ── Navigation: load the page ──────────────────────
                    try:
                        await page.goto(url, wait_until=NAV_WAIT, timeout=PAGE_TIMEOUT_MS)
                    except Exception as e:
                        print(f"[Crawler] Navigation timeout/error for {url}: {e}")

                    # ── SPA hydration: wait for framework to bootstrap ─
                    # 1. Wait for network to calm (bundles downloading)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=10000)
                    except Exception:
                        pass  # Timeout OK — SPAs with websockets never idle

                    # 2. Wait for framework to render interactive elements
                    #    SPAs start as empty <app-root></app-root> shells —
                    #    we need to wait for actual content to appear.
                    try:
                        await page.wait_for_selector(
                            'a[href], input, button, [role="link"], [role="button"], '
                            'form, textarea, select, [ng-reflect-router-link]',
                            timeout=8000,
                        )
                    except Exception:
                        pass  # Page might genuinely have none

                    # 3. Post-render stabilization — let Angular/React/Vue
                    #    finish any deferred rendering, lazy-loaded modules,
                    #    and background API calls after initial bootstrap.
                    await page.wait_for_timeout(2000)

                    # ── User interaction: uncover hidden content ───────
                    await self._simulate_user_interaction_async(page)

                    page_urls = await self._extract_links_async(page, url)
                    page_forms = await self._extract_forms_async(page, url)
                    page_urls.update(await self._extract_spa_routes_async(page))

                    if "#/" not in url:
                        hash_urls, hash_forms = await self._explore_hash_routes_async(
                            page, url, api_requests, api_seen, network_urls,
                        )
                        visited.update(hash_urls)
                        page_forms.extend(hash_forms)
                        network_urls.update(hash_urls)

                except Exception as e:
                    print(f"[Crawler] Error on {url}: {e}")
                finally:
                    if page:
                        try:
                            await page.close()
                        except Exception:
                            pass

                all_forms.extend(page_forms)
                for link in page_urls:
                    if "#/" in link:
                        continue
                    if link not in visited:
                        queue.append((link, depth + 1))

            await context.close()
            await browser.close()

        extra = set()
        extra.update(self._fetch_robots_txt())
        extra.update(self._fetch_sitemap())

        synthetic_forms = self._api_requests_to_forms(api_requests)
        all_forms.extend(synthetic_forms)
        if synthetic_forms:
            print(f"[Crawler] Converted {len(synthetic_forms)} API endpoints into injectable forms")

        all_urls = list(dict.fromkeys(
            list(visited) + list(network_urls) + list(extra)
        ))
        forms    = self._dedup_forms(all_forms)

        print(f"[Crawler] Complete: {len(all_urls)} URLs, {len(forms)} forms")
        return {"urls": all_urls, "forms": forms}

    # ------------------------------------------------------------------
    # Async Playwright helpers
    # ------------------------------------------------------------------

    async def _extract_links_async(self, page, base_url: str) -> Set[str]:
        links: Set[str] = set()
        try:
            hrefs = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                         .map(a => a.href)
            """)
            for href in hrefs:
                url = self._normalize_url(href, base_url)
                if (
                    url
                    and self._same_domain(url)
                    and not self._skip_url(url)
                    and not self._is_logout_url(url)
                ):
                    links.add(url)
        except Exception:
            pass
        return links

    async def _extract_forms_async(self, page, base_url: str) -> List[Dict]:
        forms = []
        try:
            raw_forms = await page.evaluate("""
                () => {
                    const results = Array.from(document.querySelectorAll('form')).map(f => ({
                        action: f.action || '',
                        method: f.method || 'get',
                        inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                            name:  i.name  || i.id || '',
                            type:  i.type  || 'text',
                            value: i.value || '',
                        })),
                        _source: 'form-tag',
                    }));
                    const orphanInputs = Array.from(
                        document.querySelectorAll('input, textarea, select')
                    ).filter(el => !el.closest('form'));
                    if (orphanInputs.length > 0) {
                        const containers = new Map();
                        for (const inp of orphanInputs) {
                            const container =
                                inp.closest('[role="form"], fieldset, dialog, section, .form, .login, .search, .auth, .signup, .register, .contact') ||
                                inp.parentElement;
                            const key = container || document.body;
                            if (!containers.has(key)) containers.set(key, []);
                            containers.get(key).push(inp);
                        }
                        for (const [container, inputs] of containers.entries()) {
                            const btn = container.querySelector(
                                'button[type="submit"], button:not([type]), input[type="submit"], [role="button"]'
                            );
                            let action = '';
                            if (btn) {
                                action = btn.getAttribute('formaction') || '';
                            }
                            if (!action) {
                                action = container.getAttribute('data-action') || container.getAttribute('action') || '';
                            }
                            results.push({
                                action: action || window.location.href,
                                method: 'post',
                                inputs: inputs.map(i => ({
                                    name:  i.name || i.id || i.getAttribute('aria-label') || i.placeholder || 'unknown',
                                    type:  i.type || 'text',
                                    value: i.value || '',
                                })),
                                _source: 'spa-floating',
                            });
                        }
                    }
                    return results;
                }
            """)
            for f in raw_forms:
                action = f.get("action") or base_url
                if not action.startswith("http"):
                    action = urljoin(base_url, action)
                inputs = [i for i in f.get("inputs", []) if i.get("name")]
                if inputs:
                    forms.append({
                        "action": action,
                        "method": f.get("method", "get").lower(),
                        "inputs": inputs,
                    })
        except Exception:
            pass
        return forms

    async def _extract_spa_routes_async(self, page) -> Set[str]:
        routes: Set[str] = set()
        try:
            next_data = await page.evaluate("() => window.__NEXT_DATA__")
            if next_data:
                for p in next_data.get("pages", []):
                    url = urljoin(self.base_url, p)
                    if self._same_domain(url):
                        routes.add(url)
            app_routes = await page.evaluate("() => window.__routes || []")
            if isinstance(app_routes, list):
                for r in app_routes:
                    if isinstance(r, str) and r.startswith("/"):
                        routes.add(urljoin(self.base_url, r))
        except Exception:
            pass
        return routes

    async def _simulate_user_interaction_async(self, page):
        try:
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(600)
            await page.evaluate("window.scrollTo(0, 0)")
            await page.wait_for_timeout(300)

            await self._click_nav_items_async(page)

            modal_selectors = [
                "button[data-toggle='modal']",
                "button[data-bs-toggle='modal']",
                "[data-modal]",
                "button:has-text('Login')",
                "button:has-text('Sign')",
                "button:has-text('Register')",
                "button:has-text('Contact')",
                "button:has-text('Try')",
                "button:has-text('Get Started')",
                "button:has-text('Submit')",
                "a:has-text('Login')",
                "a:has-text('Sign')",
                "a:has-text('Register')",
            ]
            for selector in modal_selectors:
                try:
                    els = await page.query_selector_all(selector)
                    for el in els[:2]:
                        try:
                            await el.click(timeout=1500)
                            await page.wait_for_timeout(800)
                        except Exception:
                            pass
                except Exception:
                    pass

            hover_selectors = [
                ".dropdown-toggle", "[data-toggle='dropdown']",
                ".has-submenu", ".menu-item-has-children > a",
            ]
            for selector in hover_selectors:
                try:
                    els = await page.query_selector_all(selector)
                    for el in els[:3]:
                        try:
                            await el.hover(timeout=1000)
                            await page.wait_for_timeout(400)
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass

    async def _click_nav_items_async(self, page):
        nav_selectors = [
            "nav a", "[role='navigation'] a", ".navbar a",
            ".nav-link", ".menu-item a", "header a",
        ]
        for selector in nav_selectors:
            try:
                elements = await page.query_selector_all(selector)
                for el in elements[:5]:
                    try:
                        await el.click(timeout=1000)
                        await page.wait_for_timeout(500)
                    except Exception:
                        pass
            except Exception:
                pass

    async def _explore_hash_routes_async(
        self, page, current_url, api_requests, api_seen, network_urls,
    ) -> Tuple[Set[str], List[Dict]]:
        discovered_urls: Set[str] = set()
        discovered_forms: List[Dict] = []
        try:
            hash_links = await page.evaluate("""
                () => {
                    const links = new Set();
                    document.querySelectorAll('a[href]').forEach(a => {
                        const href = a.getAttribute('href') || '';
                        const idx = href.indexOf('#/');
                        if (idx !== -1) {
                            links.add(href.substring(idx));
                        }
                    });
                    return Array.from(links);
                }
            """)
            if not hash_links:
                return discovered_urls, discovered_forms

            base = current_url.split("#")[0]
            if not base.endswith("/"):
                base += "/"
            print(f"[Crawler] SPA hash routes found: {len(hash_links)}")

            visited_hashes: Set[str] = set()
            for hash_route in hash_links[:15]:
                if hash_route in visited_hashes:
                    continue
                visited_hashes.add(hash_route)
                full_url = f"{base}{hash_route}"
                discovered_urls.add(full_url)
                print(f"[Crawler]   Visiting hash route: {hash_route}")
                try:
                    await page.evaluate("hash => window.location.hash = hash", hash_route)
                    await page.wait_for_timeout(1500)
                    route_forms = await self._extract_forms_async(page, full_url)
                    discovered_forms.extend(route_forms)
                    if route_forms:
                        print(f"[Crawler]     -> {len(route_forms)} forms in {hash_route}")
                except Exception:
                    pass
        except Exception:
            pass
        return discovered_urls, discovered_forms

    async def _sync_cookies_async(self, context):
        cookies = []
        for c in self.session.cookies:
            cookies.append({
                "name":   c.name,
                "value":  c.value,
                "domain": c.domain or self.domain,
                "path":   c.path or "/",
            })
        if cookies:
            await context.add_cookies(cookies)
            print(f"[Crawler] Synced {len(cookies)} session cookies to Playwright")

    def _api_requests_to_forms(self, api_requests: List[Dict]) -> List[Dict]:
        """
        Convert intercepted fetch/XHR requests into synthetic form dicts
        so injection modules (SQLi, XSS, etc.) can target them.
        """
        forms: List[Dict] = []

        for api in api_requests:
            url         = api.get("url", "")
            method      = api.get("method", "GET").lower()
            post_data   = api.get("post_data")
            content_type = api.get("content_type", "")
            parsed      = urlparse(url)
            base_url    = urlunparse(parsed._replace(query="", fragment=""))
            inputs: List[Dict] = []

            # Extract query parameters as inputs
            if parsed.query:
                for key, values in parse_qs(parsed.query).items():
                    inputs.append({
                        "name": key,
                        "type": "text",
                        "value": values[0] if values else "",
                    })

            # Extract POST body parameters
            if post_data:
                if "application/json" in content_type:
                    try:
                        body = json.loads(post_data)
                        if isinstance(body, dict):
                            for key, val in body.items():
                                inputs.append({
                                    "name": key,
                                    "type": "text",
                                    "value": str(val) if not isinstance(val, (dict, list)) else "",
                                })
                    except (json.JSONDecodeError, TypeError):
                        pass
                elif "application/x-www-form-urlencoded" in content_type or not content_type:
                    try:
                        for key, values in parse_qs(post_data).items():
                            inputs.append({
                                "name": key,
                                "type": "text",
                                "value": values[0] if values else "",
                            })
                    except Exception:
                        pass

            if inputs:
                forms.append({
                    "action": base_url,
                    "method": method,
                    "inputs": inputs,
                    "_source": "network-intercept",
                })
            elif method != "get":
                # POST/PUT/DELETE with no extractable body — still worth testing
                forms.append({
                    "action": base_url,
                    "method": method,
                    "inputs": [{"name": "data", "type": "text", "value": ""}],
                    "_source": "network-intercept",
                })

        return forms

    def _detect_spa(self, page: Any) -> bool:
        """Detect if page is a React/Vue/Angular/modern SPA.

        Uses broad heuristics so we don't miss SPAs that tree-shake
        global framework objects (e.g. production Next.js builds).
        """
        try:
            indicators = page.evaluate("""
                () => ({
                    react:    !!(window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__
                                 || document.querySelector('[data-reactroot]')
                                 || document.querySelector('#__next')
                                 || document.querySelector('#root')),
                    vue:      !!(window.Vue || window.__VUE__
                                 || document.querySelector('[data-v-]')
                                 || document.querySelector('#app')),
                    angular:  !!(window.angular || window.ng
                                 || document.querySelector('[ng-version]')
                                 || document.querySelector('app-root')),
                    next:     !!(window.__NEXT_DATA__ || window.__NUXT__),
                    generic:  !!(document.querySelector('script[src*="chunk"]')
                                 || document.querySelector('script[src*="bundle"]')
                                 || document.querySelector('script[type="module"]')),
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
                if (
                    link
                    and self._same_domain(link)
                    and not self._skip_url(link)
                    and not self._is_logout_url(link)
                ):
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
        if href.startswith(("mailto:", "tel:", "javascript:", "data:")):
            return None
        # Skip pure anchors (#section) but KEEP SPA hash routes (#/login)
        if href.startswith("#") and not href.startswith("#/"):
            return None
        url = urljoin(base, href)
        parsed = urlparse(url)
        # Preserve SPA hash routes (e.g. #/login, #/register)
        if parsed.fragment and parsed.fragment.startswith("/"):
            return urlunparse(parsed)
        # Strip regular anchor fragments
        return urlunparse(parsed._replace(fragment=""))

    def _same_domain(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self.domain
        except Exception:
            return False

    def _skip_url(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)

    def _is_logout_url(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        logout_keywords = ("logout", "signout", "log-out", "sign-out")
        return any(keyword in path for keyword in logout_keywords)

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
