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
from copy import deepcopy
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urljoin, urlparse, urlunparse, parse_qs

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
OPENAPI_CANDIDATE_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v3/api-docs",
)
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


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
            results = asyncio.run(self._crawl_playwright_async())
        else:
            print("[Crawler] Playwright not available — using BeautifulSoup (static only)")
            results = self._crawl_bs4()
        return self._augment_with_openapi(results)

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

    def _augment_with_openapi(self, results: Dict[str, Any]) -> Dict[str, Any]:
        spec_doc, spec_url = self._fetch_openapi_spec()
        if not spec_doc:
            return results

        spec_urls, spec_forms = self._openapi_to_targets(spec_doc, spec_url)
        if spec_urls or spec_forms:
            print(
                f"[Crawler] OpenAPI import: {len(spec_urls)} URLs, "
                f"{len(spec_forms)} forms from {spec_url}"
            )

        merged_urls = list(dict.fromkeys(results.get("urls", []) + spec_urls))
        merged_forms = self._dedup_forms(results.get("forms", []) + spec_forms)
        return {"urls": merged_urls, "forms": merged_forms}

    def _fetch_openapi_spec(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        origin = self._origin_url()
        for candidate in OPENAPI_CANDIDATE_PATHS:
            spec_url = urljoin(f"{origin}/", candidate.lstrip("/"))
            try:
                resp = self.session.get(spec_url, timeout=self.timeout)
            except Exception:
                continue

            if resp.status_code != 200:
                continue

            doc = self._parse_openapi_document(resp.text)
            if self._looks_like_openapi(doc):
                return doc, spec_url
        return None, None

    def _parse_openapi_document(self, raw_text: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = json.loads(raw_text)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            try:
                import yaml

                parsed = yaml.safe_load(raw_text)
                return parsed if isinstance(parsed, dict) else None
            except Exception:
                return None

    def _looks_like_openapi(self, doc: Optional[Dict[str, Any]]) -> bool:
        if not isinstance(doc, dict):
            return False
        return bool(doc.get("paths")) and ("openapi" in doc or "swagger" in doc)

    def _openapi_to_targets(
        self, spec_doc: Dict[str, Any], spec_url: Optional[str]
    ) -> Tuple[List[str], List[Dict[str, Any]]]:
        urls: List[str] = []
        forms: List[Dict[str, Any]] = []
        paths = spec_doc.get("paths", {}) or {}

        for raw_path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method, operation in path_item.items():
                if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                    continue

                resolved_path = self._materialize_openapi_path(
                    raw_path, path_item, operation, spec_doc
                )
                if not resolved_path:
                    continue

                endpoint_url = urljoin(
                    f"{self._api_server_base(spec_doc, spec_url)}/",
                    resolved_path.lstrip("/"),
                )
                parameters = self._collect_openapi_parameters(path_item, operation)
                extra_headers, extra_cookies, extra_query = self._openapi_security_context(
                    spec_doc, path_item, operation
                )

                if method.lower() == "get":
                    query_params = {
                        param["name"]: self._sample_value_for_schema(
                            param.get("schema"), param.get("example"), spec_doc
                        )
                        for param in parameters
                        if param.get("in") == "query" and param.get("name")
                    }
                    query_params.update(extra_query)
                    if query_params:
                        urls.append(f"{endpoint_url}?{urlencode(query_params)}")
                    else:
                        urls.append(endpoint_url)
                form = self._build_openapi_form(
                    endpoint_url,
                    method,
                    operation,
                    parameters,
                    spec_doc,
                    extra_headers,
                    extra_cookies,
                    extra_query,
                )
                if form:
                    forms.append(form)

        return urls, forms

    def _api_server_base(
        self, spec_doc: Dict[str, Any], spec_url: Optional[str]
    ) -> str:
        servers = spec_doc.get("servers") or []
        if servers:
            first = servers[0]
            if isinstance(first, dict) and first.get("url"):
                return urljoin((spec_url or self._origin_url()) + "/", first["url"])
        return self._origin_url()

    def _origin_url(self) -> str:
        parsed = urlparse(self.base_url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _collect_openapi_parameters(
        self, path_item: Dict[str, Any], operation: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        merged: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str]] = set()
        for source in (path_item.get("parameters") or [], operation.get("parameters") or []):
            for param in source:
                if not isinstance(param, dict):
                    continue
                key = (param.get("in", ""), param.get("name", ""))
                if key in seen:
                    continue
                seen.add(key)
                merged.append(param)
        return merged

    def _materialize_openapi_path(
        self,
        raw_path: str,
        path_item: Dict[str, Any],
        operation: Dict[str, Any],
        spec_doc: Dict[str, Any],
    ) -> Optional[str]:
        materialized = raw_path
        for param in self._collect_openapi_parameters(path_item, operation):
            if param.get("in") != "path" or not param.get("name"):
                continue
            placeholder = "{" + param["name"] + "}"
            sample = self._sample_value_for_schema(
                param.get("schema"), param.get("example"), spec_doc
            )
            materialized = materialized.replace(placeholder, str(sample))
        return None if "{" in materialized or "}" in materialized else materialized

    def _build_openapi_form(
        self,
        endpoint_url: str,
        method: str,
        operation: Dict[str, Any],
        parameters: List[Dict[str, Any]],
        spec_doc: Dict[str, Any],
        extra_headers: Dict[str, str],
        extra_cookies: Dict[str, str],
        extra_query: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        request_body = operation.get("requestBody") or {}
        content = request_body.get("content") or {}
        header_inputs = self._build_openapi_param_inputs(parameters, "header", spec_doc)
        cookie_inputs = self._build_openapi_param_inputs(parameters, "cookie", spec_doc)

        for content_type in (
            "application/json",
            "application/xml",
            "text/xml",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        ):
            media = content.get(content_type)
            if not isinstance(media, dict):
                continue

            schema = media.get("schema") or {}
            if content_type in ("application/xml", "text/xml"):
                inputs = [{"name": "xml", "type": "text", "value": "<root>sample</root>"}]
            else:
                sample_body = self._sample_object_from_schema(schema, spec_doc)
                inputs = [
                    {"name": key, "type": "text", "value": value}
                    for key, value in sample_body.items()
                ]
                if not inputs:
                    inputs = [{"name": "data", "type": "text", "value": ""}]

            return {
                "action": endpoint_url,
                "method": method.lower(),
                "inputs": [
                    *inputs,
                    *[
                        {"name": key, "type": "text", "value": value}
                        for key, value in extra_query.items()
                    ],
                ],
                "header_inputs": header_inputs,
                "cookie_inputs": cookie_inputs,
                "extra_headers": extra_headers,
                "extra_cookies": extra_cookies,
                "content_type": content_type,
                "body_format": (
                    "json" if content_type == "application/json"
                    else "xml" if content_type in ("application/xml", "text/xml")
                    else "form"
                ),
                "_source": "openapi",
            }
        if method.lower() == "get" and (header_inputs or cookie_inputs):
            return {
                "action": endpoint_url,
                "method": "get",
                "inputs": [
                    {"name": key, "type": "text", "value": value}
                    for key, value in extra_query.items()
                ],
                "header_inputs": header_inputs,
                "cookie_inputs": cookie_inputs,
                "extra_headers": extra_headers,
                "extra_cookies": extra_cookies,
                "content_type": "text/plain",
                "body_format": "form",
                "_source": "openapi",
            }
        return None

    def _sample_object_from_schema(
        self, schema: Dict[str, Any], spec_doc: Dict[str, Any]
    ) -> Dict[str, str]:
        resolved = self._resolve_schema(schema, spec_doc)
        if not isinstance(resolved, dict):
            return {}

        example = resolved.get("example")
        if isinstance(example, dict):
            return {
                str(key): self._stringify_sample_value(value)
                for key, value in example.items()
            }

        properties = resolved.get("properties") or {}
        if not isinstance(properties, dict):
            return {}

        samples: Dict[str, str] = {}
        for name, prop_schema in properties.items():
            samples[name] = self._sample_value_for_schema(prop_schema, None, spec_doc)
        return samples

    def _build_openapi_param_inputs(
        self, parameters: List[Dict[str, Any]], location: str, spec_doc: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        inputs: List[Dict[str, str]] = []
        for param in parameters:
            if param.get("in") != location or not param.get("name"):
                continue
            inputs.append({
                "name": param["name"],
                "type": "text",
                "value": self._sample_value_for_schema(
                    param.get("schema"), param.get("example"), spec_doc
                ),
            })
        return inputs

    def _openapi_security_context(
        self,
        spec_doc: Dict[str, Any],
        path_item: Dict[str, Any],
        operation: Dict[str, Any],
    ) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
        requirements = operation.get("security")
        if requirements is None:
            requirements = path_item.get("security")
        if requirements is None:
            requirements = spec_doc.get("security")
        if not requirements:
            return {}, {}, {}

        schemes = (
            spec_doc.get("components", {}).get("securitySchemes", {}) or {}
        )
        session_headers = dict(self.session.headers or {})
        session_cookies = {}
        try:
            session_cookies = {c.name: c.value for c in self.session.cookies}
        except Exception:
            session_cookies = dict(getattr(self.session, "cookies", {}) or {})
        session_query = dict(getattr(self.session, "_default_query_params", {}) or {})

        extra_headers: Dict[str, str] = {}
        extra_cookies: Dict[str, str] = {}
        extra_query: Dict[str, str] = {}

        for requirement in requirements:
            if not isinstance(requirement, dict):
                continue
            local_headers: Dict[str, str] = {}
            local_cookies: Dict[str, str] = {}
            local_query: Dict[str, str] = {}
            satisfied = True

            for scheme_name in requirement.keys():
                scheme = schemes.get(scheme_name)
                if not isinstance(scheme, dict):
                    satisfied = False
                    break

                scheme_type = scheme.get("type")
                if scheme_type == "http" and scheme.get("scheme", "").lower() == "bearer":
                    auth_header = session_headers.get("Authorization")
                    if auth_header:
                        local_headers["Authorization"] = auth_header
                    else:
                        satisfied = False
                        break
                elif scheme_type == "apiKey":
                    key_name = scheme.get("name")
                    location = scheme.get("in")
                    if location == "header" and key_name in session_headers:
                        local_headers[key_name] = session_headers[key_name]
                    elif location == "cookie" and key_name in session_cookies:
                        local_cookies[key_name] = session_cookies[key_name]
                    elif location == "query" and key_name in session_query:
                        local_query[key_name] = session_query[key_name]
                    else:
                        satisfied = False
                        break

            if satisfied:
                extra_headers.update(local_headers)
                extra_cookies.update(local_cookies)
                extra_query.update(local_query)
                return extra_headers, extra_cookies, extra_query

        return {}, {}, {}

    def _sample_value_for_schema(
        self,
        schema: Optional[Dict[str, Any]],
        explicit_example: Any,
        spec_doc: Dict[str, Any],
    ) -> str:
        if explicit_example is not None:
            return self._stringify_sample_value(explicit_example)

        resolved = self._resolve_schema(schema or {}, spec_doc)
        if not isinstance(resolved, dict):
            return "sample"
        if resolved.get("example") is not None:
            return self._stringify_sample_value(resolved["example"])
        if resolved.get("default") is not None:
            return self._stringify_sample_value(resolved["default"])

        enum = resolved.get("enum")
        if isinstance(enum, list) and enum:
            return self._stringify_sample_value(enum[0])

        schema_type = resolved.get("type")
        if schema_type in {"integer", "number"}:
            return "1"
        if schema_type == "boolean":
            return "true"
        if schema_type == "array":
            return ""
        return "sample"

    def _resolve_schema(
        self, schema: Dict[str, Any], spec_doc: Dict[str, Any]
    ) -> Dict[str, Any]:
        if not isinstance(schema, dict):
            return {}

        ref = schema.get("$ref")
        if not ref or not ref.startswith("#/"):
            return schema

        current: Any = spec_doc
        for part in ref[2:].split("/"):
            if not isinstance(current, dict):
                return schema
            current = current.get(part)

        if isinstance(current, dict):
            merged = deepcopy(current)
            merged.update({k: v for k, v in schema.items() if k != "$ref"})
            return merged
        return schema

    def _stringify_sample_value(self, value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            return ""
        return str(value)

    def _dedup_forms(self, forms: List[Dict]) -> List[Dict]:
        seen:   Set[tuple]  = set()
        unique: List[Dict]  = []
        for f in forms:
            key = (
                f.get("action", ""),
                f.get("method", ""),
                f.get("content_type", ""),
                tuple(sorted(i.get("name", "") for i in f.get("inputs", []))),
            )
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
