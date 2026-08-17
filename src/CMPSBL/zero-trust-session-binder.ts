// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-CMPSBL-Commercial-1.0
/**
 * S-Tier 082 — Zero-Trust Session Binder
 * CJPI: 91 | Node: IDENTITY | ID: S-79
 *
 * Binds sessions to device/browser fingerprints with continuous
 * re-validation. Detects session hijacking attempts.
 */

export interface SessionBinding {
  sessionId: string;
  fingerprint: string;
  userId: string;
  boundAt: number;
  lastVerified: number;
  trustScore: number; // 0-100
}

export interface BindingVerification {
  valid: boolean;
  trustScore: number;
  anomalies: string[];
}

const bindings = new Map<string, SessionBinding>();

export function bindSession(sessionId: string, userId: string, fingerprint: string): SessionBinding {
  const binding: SessionBinding = {
    sessionId, fingerprint, userId,
    boundAt: Date.now(), lastVerified: Date.now(), trustScore: 100,
  };
  bindings.set(sessionId, binding);
  return binding;
}

export function verifyBinding(sessionId: string, currentFingerprint: string): BindingVerification {
  const binding = bindings.get(sessionId);
  if (!binding) return { valid: false, trustScore: 0, anomalies: ['Unknown session'] };

  const anomalies: string[] = [];
  let trustDelta = 0;

  // Fingerprint mismatch
  if (binding.fingerprint !== currentFingerprint) {
    anomalies.push('Fingerprint changed — possible session hijacking');
    trustDelta -= 50;
  }

  // Session age check
  const ageHours = (Date.now() - binding.boundAt) / 3_600_000;
  if (ageHours > 24) {
    anomalies.push('Session older than 24 hours');
    trustDelta -= 10;
  }

  binding.trustScore = Math.max(0, Math.min(100, binding.trustScore + trustDelta));
  binding.lastVerified = Date.now();

  return {
    valid: anomalies.length === 0 && binding.trustScore >= 50,
    trustScore: binding.trustScore,
    anomalies,
  };
}

export function revokeSession(sessionId: string): boolean { return bindings.delete(sessionId); }
export function getBinding(sessionId: string): SessionBinding | null { return bindings.get(sessionId) ?? null; }
