import {
  bindSession, verifyBinding, revokeSession
} from "./src/cmpsbl/zero-trust-session-binder";
import {
  createLimiter, tryConsume, adaptLimit, getLimiter
} from "./src/cmpsbl/adaptive-rate-limiting";
import { AuditGradeDecisionLedger } from "./src/cmpsbl/audit-grade-decision-ledger";
import { redactSecrets, scrubText } from "./src/cmpsbl/redact-secrets";

const assert = (v: unknown, msg: string) => { if (!v) throw new Error(msg); };

const s = bindSession("s1", "u1", "fp1");
assert(s.trustScore === 100, "binding initial trust");
assert(verifyBinding("s1", "fp1").valid, "same fingerprint should validate");
const changed = verifyBinding("s1", "fp2");
assert(!changed.valid && changed.trustScore === 50, "changed fingerprint should degrade trust");
assert(revokeSession("s1"), "revocation");

createLimiter("r1", 2, 0.1);
assert(tryConsume("r1"), "token 1");
assert(tryConsume("r1"), "token 2");
assert(!tryConsume("r1"), "third token denied");
adaptLimit("r1", 0.5);
assert((getLimiter("r1")?.maxTokens ?? 0) >= 1, "adaptive floor");

const ledger = new AuditGradeDecisionLedger();
ledger.record("auth", "u1", "signin", redactSecrets({ password: "secret123", keep: 7 }));
ledger.record("auth", "u1", "signout");
assert(ledger.verify().valid, "ledger chain");
assert(JSON.stringify(ledger.getEntries()).includes("[REDACTED]"), "ledger context redacted");
assert(!scrubText("Authorization: Bearer eyJabcdef.eyJabcdef.abcdefgh").includes("eyJabcdef"), "embedded token scrubbed");

console.log("CMPSBL integration tests: PASS");
