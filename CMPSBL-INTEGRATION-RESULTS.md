# CMPSBL Real-World Integration Results

## Result

A concrete Door-1 integration was produced from the uploaded Collective Master Library v3.0.4 against the forked `auth-starter-backend`.

### Integrated canonical capabilities

| Capability | CML source | SHA-256 manifest match |
|---|---|---|
| `zero-trust-session-binder.ts` | `source/src/crownjewels/s-tier/082-zero-trust-session-binder.ts` | PASS |
| `adaptive-rate-limiting.ts` | `source/src/crownjewels/s-tier/066-adaptive-rate-limiting.ts` | PASS |
| `audit-grade-decision-ledger.ts` | `source/bldbl/src/blocks/eng/audit-grade-decision-ledger/index.ts` | PASS |
| `redact-secrets.ts` | `source/bldbl/src/blocks/prm/redact-secrets/index.ts` | PASS |

### Host wiring

- `signup.ts`: binds the new session and writes an auth receipt.
- `signin.ts`: binds the new session and writes an auth receipt.
- `checkauth.ts`: continuously verifies the session binding, couples trust to adaptive token-bucket capacity, returns 401 on trust failure and 429 on rate exhaustion.
- `signout.ts`: revokes the CMPSBL session binding and records revocation.
- `auth-governance.ts`: thin host-specific adapter. This file is integration glue, not represented as a pre-existing CML capability.
- Secret redaction is applied before context enters the audit ledger.

### Verification performed in this sandbox

- Canonical copied CML source files were checked against the CML `CHECKSUMS.sha256` manifest.
- Integration points were mechanically checked after patching.
- A deterministic `cmpsbl-integration-test.ts` was added for binder, limiter, ledger, and redactor behavior.

### Environment limitation

The sandbox does not contain Bun and the fork has no installed `node_modules`. Therefore the Bun application and integration test could not be executed here. A global `tsc` invocation was attempted, but it cannot resolve the fork's dependencies or Bun types and therefore is **not** a valid application typecheck. This artifact must not be described as runtime-verified until `bun install` and the included test/build commands pass in a Bun environment.

## Reproduce

```bash
bun install
bun run cmpsbl-integration-test.ts
bun run src/index.ts
```

This is an experimental integration artifact, not a security audit or production certification.
