// CMPSBL integration adapter for auth-starter-backend.
// Door 1 / AGPL integration. Canonical capability implementations are adjacent.

import type { Context } from "hono";
import { bindSession, verifyBinding, revokeSession } from "./zero-trust-session-binder";
import { createLimiter, getLimiter, adaptLimit, tryConsume } from "./adaptive-rate-limiting";
import { AuditGradeDecisionLedger } from "./audit-grade-decision-ledger";
import { redactSecrets } from "./redact-secrets";

export const authLedger = new AuditGradeDecisionLedger();

function hashFingerprint(input: string): string {
  // Fingerprint is intentionally coarse and non-secret. It is a continuity signal,
  // not a claim of unique device identity.
  let h = 2166136261;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

export function requestFingerprint(c: Context): string {
  const ua = c.req.header("user-agent") ?? "unknown";
  const lang = c.req.header("accept-language") ?? "unknown";
  return hashFingerprint(`${ua}|${lang}`);
}

export function governNewSession(c: Context, sessionId: string, userId: string) {
  const fingerprint = requestFingerprint(c);
  const binding = bindSession(sessionId, userId, fingerprint);
  createLimiter(sessionId, 20, 2);
  authLedger.record("session", userId, "bind", redactSecrets({
    sessionId: "[REDACTED]",
    trustScore: binding.trustScore,
  }));
  return binding;
}

export function governExistingSession(c: Context, sessionId: string) {
  const verification = verifyBinding(sessionId, requestFingerprint(c));

  let limiter = getLimiter(sessionId);
  if (!limiter) limiter = createLimiter(sessionId, 10, 1);

  // Couple request allowance to current session trust. Repeated anomalies shrink
  // capacity; healthy sessions recover toward their baseline.
  const factor = verification.trustScore >= 90 ? 1.05 :
                 verification.trustScore >= 50 ? 0.75 : 0.35;
  adaptLimit(sessionId, factor);

  const allowed = tryConsume(sessionId, 1);
  if (!verification.valid || !allowed) {
    authLedger.record("session", "session-holder", "deny", {
      trustScore: verification.trustScore,
      anomalies: verification.anomalies,
      rateAllowed: allowed,
    });
  }
  return { verification, allowed };
}

export function governSessionRevocation(sessionId: string) {
  revokeSession(sessionId);
  authLedger.record("session", "session-holder", "revoke", { sessionId: "[REDACTED]" });
}
