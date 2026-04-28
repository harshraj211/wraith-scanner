# Wraith Future Plan

The active product roadmap is maintained in [Full_future_plan.md](Full_future_plan.md).

Use that file for the current frontend, desktop agent, controlled browser, proxy capture, manual tools, scanner-depth, reporting, and installer plan.

Current implementation status:

- Manual Workbench now has proxy capture, Repeater, Intruder, Decoder, response diffs, and corpus-backed request history.
- Proof Mode skeleton is underway with deterministic task creation, policy checks, evidence persistence, and a safe open-redirect proof executor.
- Authorization Matrix / BOLA v1 is now underway with safe role-diff replay from the corpus, `authz` evidence storage, and frontend Proof Mode controls.
- Nuclei integration v1 is implemented with a safe local adapter, `/api/integrations/nuclei/run`, corpus target selection, canonical finding import, evidence persistence, and Automated Workspace controls.
