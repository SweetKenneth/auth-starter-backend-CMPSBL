# CMPSBL CML Integration Provenance

Target: `auth-starter-backend-CMPSBL-main`

Integration basis: Agent Kit r3.0.12 / Collective Master Library v3.0.4, Door 1 (AGPL).

Canonical CML source copied without semantic modification:
- S-Tier 082 / STIER-S-79 — Zero-Trust Session Binder
- S-Tier 066 / STIER-S-ACC02 — Adaptive Rate Limiting
- S-Tier 136 / Audit-Grade Decision Ledger
- BLDBL PRM — Secret Redactor

Host-specific adapter added:
- `src/cmpsbl/auth-governance.ts`

Host integration points:
- signup: bind new session + ledger receipt
- signin: bind new session + ledger receipt
- checkauth: verify binding + adapt/consume rate allowance
- signout: revoke binding + ledger receipt

This artifact is an experimental integration, not a security audit or production certification.
