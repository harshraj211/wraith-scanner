# Wraith Future Plan

The active product roadmap is maintained in [Full_future_plan.md](Full_future_plan.md), with the enterprise phase roadmap tracked in [docs/ENTERPRISE_UPGRADE_PLAN.md](docs/ENTERPRISE_UPGRADE_PLAN.md).

Use that file for the current frontend, desktop agent, controlled browser, proxy capture, manual tools, scanner-depth, reporting, and installer plan.

Current implementation status:

- Manual Workbench now has proxy capture, local CA preparation, Repeater, Intruder, Decoder, Comparer, response diffs, and corpus-backed request history.
- Proof Mode skeleton is underway with deterministic task creation, policy checks, evidence persistence, and a safe open-redirect proof executor.
- Authorization Matrix / BOLA v1 is now underway with safe role-diff replay from the corpus, `authz` evidence storage, and frontend Proof Mode controls.
- Nuclei integration v1 is implemented with a safe local adapter, `/api/integrations/nuclei/run`, corpus target selection, canonical finding import, evidence persistence, and Automated Workspace controls.
- Managed Nuclei assets are implemented for desktop/web use: status, engine install/update, template update, and Wraith-owned template directories remove the need for terminal setup.
- CVE intelligence v1 is implemented for CVE-backed findings with NVD metadata, FIRST EPSS scoring, CISA KEV flags, persisted finding metadata, and an Automated Workspace enrichment action.
