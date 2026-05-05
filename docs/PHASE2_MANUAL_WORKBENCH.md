# Phase 2 Manual Workbench Status

Phase 2 moves Wraith closer to a Burp-style manual testing workflow while keeping safety controls and evidence-first storage.

## Completed in this phase

- Corpus request history now includes latest response metadata:
  - status code
  - content type
  - content length
  - response time
- Proxy History UI now has:
  - method/status/path filters
  - refresh action
  - selected request/response inspector
- Repeater now supports saving requests into the corpus without sending them.
- Intruder now supports:
  - grep-match text checks
  - regex extraction from response excerpts
  - result columns for match/extract signals
- Added passive scanner foundation over captured traffic:
  - missing Content-Security-Policy
  - missing HSTS on HTTPS
  - missing X-Content-Type-Options
  - missing frame protection
- Proxy UI can trigger passive scanning for the active scan.

## Current limits

- Proxy is still plain HTTP forwarding/capture only; HTTPS MITM certificate flow is not implemented yet.
- Passive scanner is intentionally low-noise and header-focused; it should expand into cookies, CORS, cache headers, mixed content, reflected parameters, and disclosure checks.
- Intruder is capped and safe-mode oriented; it still needs payload-position sets, grep-extract persistence, sorting, and clustering controls.

## Next recommended Phase 2 work

1. HTTPS MITM setup flow with explicit certificate install guidance.
2. Proxy interception editor for pending requests, not just forward/drop controls.
3. Passive scanner expansion for cookies, CORS, cache, and reflected inputs.
4. Manual finding creation from selected request/response evidence.
5. Repeater response diff between attempts.
