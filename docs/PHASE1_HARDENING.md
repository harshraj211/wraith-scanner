# Phase 1 Hardening Status

Phase 1 turns Wraith from a working scanner into a more repeatable, professional development project.

## Completed

- Added `.env.example` for local configuration without committing secrets.
- Added modern Python packaging metadata in `pyproject.toml`.
- Updated legacy `setup.py` metadata to match the Wraith project/repository name.
- Expanded GitHub Actions into separate backend and frontend gates.
- Added OpenAPI documentation at `docs/api/openapi.yaml`.
- Added Windows development scripts:
  - `scripts/setup_dev.ps1` — create/update local dev environment.
  - `scripts/test_all.ps1` — compile Python, run tests, build frontend.
  - `scripts/run_dev.ps1` — run API and React frontend together.
- Fixed Windows SQLite handle cleanup in storage tests/repository close logic.

## Current quality gate

Run locally:

```powershell
.\scripts\test_all.ps1
```

Expected gate:

- Python compile check passes.
- Backend test suite passes.
- React production build passes.

Last local verification during Phase 1:

- `103 passed`
- React build compiled successfully.

## Next phase focus

Phase 2 should focus on the Burp-like manual testing core:

1. Proxy history as first-class evidence corpus.
2. Repeater request tabs and saved requests.
3. Intruder payload-position engine, match/extract, and result clustering.
4. Passive scanner from captured traffic.
5. Manual finding creation from evidence.
