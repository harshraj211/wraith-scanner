# Wraith Remediation TODO

## P0 - Must Fix Immediately
- Restore scanner startup stability:
  - Fix syntax/import errors in `scanner/utils/waf_evasion.py`
  - Fix syntax/import errors in `scanner/modules/path_traversal_scanner.py`
  - Restore missing `XSSScanner.check_stored()` used by `main.py` and `api_server.py`
- Fix refactor regressions where URL scans pass plain parameter dicts into helpers that now expect form-style request tuples:
  - `scanner/modules/cmdi_scanner.py`
  - `scanner/modules/path_traversal_scanner.py`
  - `scanner/modules/ssti_scanner.py`
- Add smoke validation to ensure these modules import and compile before release.

## P1 - Reliability and Correctness
- Unify CLI and API execution paths so both use the same async scan pipeline.
- Add import/compile/test checks to CI:
  - `py_compile` / `compileall`
  - module import smoke tests
  - fast integration tests against `test_app`
- Tighten findings quality:
  - add baseline-aware checks to more scanners
  - persist request/response evidence for every finding
  - improve deduplication without collapsing distinct attack proofs

## P2 - DAST Depth
- Expand real stored-XSS workflow support beyond simple revisit checks.
- Add path-parameter injection support and REST-style object testing.
- Improve IDOR with cross-user / cross-role differential scanning.
- Add richer authenticated workflow replay for multi-step business flows.
- Add GraphQL discovery and testing.
- Add WebSocket capture and fuzzing.
- Add multipart/form-data insertion point coverage.

## P3 - SAST Depth
- Add Semgrep taint-mode custom rules with source/sink/sanitizer modeling.
- Improve framework coverage beyond Python and JavaScript.
- Add SARIF export and machine-readable evidence links.
- Add dependency reachability hints and SBOM ingestion.

## P4 - Industry-Level Platform Work
- Add persistent scan jobs, resumable execution, and worker queueing.
- Add multi-target scheduling and project baselines.
- Add suppression/triage workflow and policy gates.
- Add asset inventory, auth profiles, and environment-specific scan configs.
