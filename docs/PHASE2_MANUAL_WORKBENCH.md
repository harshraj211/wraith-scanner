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
- Repeater tracks recent attempts per tab and summarizes response diffs by status, length, time, body hash, and title.
- Repeater includes side-by-side body and header diff previews for recent attempts.
- Comparer now has a dedicated manual page for comparing stored corpus responses by status, timing, size, body hash, headers, and JSON semantic changes without resending traffic.
- Intruder now supports:
  - grep-match text checks
  - regex extraction from response excerpts
  - result columns for match/extract signals
- Added passive scanner foundation over captured traffic:
  - missing Content-Security-Policy
  - missing HSTS on HTTPS
  - missing X-Content-Type-Options
  - missing frame protection
  - cookie Secure / HttpOnly / SameSite weaknesses
  - wildcard and credentialed wildcard CORS
  - cacheable HTML/JSON responses
- Proxy UI can trigger passive scanning for the active scan.
- Selected proxy/corpus exchanges can be promoted into manual findings with request/response evidence linkage.
- Manual response comparison endpoint can produce response diffs and persist them as evidence artifacts when linked to a finding.
- Local CA status/generate/download/guide endpoints and Manual Testing UI controls now prepare the certificate trust layer for future scoped HTTPS interception.
- Scoped host leaf certificate generation is available for future HTTPS MITM, and CONNECT requests are scope-checked before returning the current unsupported response.

## Current limits

- Proxy is still plain HTTP forwarding/capture only; HTTPS MITM interception is not implemented yet.
- Local CA and leaf certificate generation exist, but installing the CA does not enable CONNECT interception until the guarded MITM engine is added.
- Passive scanner is intentionally low-noise; it still needs mixed content, reflected parameters, disclosure checks, and better duplicate grouping.
- Intruder is capped and safe-mode oriented; it still needs payload-position sets, grep-extract persistence, sorting, and clustering controls.

## Next recommended Phase 2 work

1. Scoped HTTPS MITM tunnel that uses the explicit CA/leaf setup, captures decrypted HTTP safely, and refuses out-of-scope CONNECT interception.
2. Proxy interception editor for pending requests, not just forward/drop controls.
3. Passive scanner expansion for reflected inputs, disclosure checks, and duplicate grouping.
4. Finding-to-evidence artifact export for reports and proof mode.
5. Persistent Repeater collections with named folders and saved diff notes.
