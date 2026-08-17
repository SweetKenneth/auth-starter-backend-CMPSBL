// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-CMPSBL-Commercial-1.0
/**
 * S-Tier 066 — Adaptive Rate Limiting
 * CJPI: 93 | Node: ACCESS | ID: S-ACC02
 *
 * Token bucket rate limiter that adapts limits based on provider health
 * and system load. Gracefully degrades under pressure.
 */

export interface RateLimiter {
  id: string;
  maxTokens: number;
  tokens: number;
  refillRate: number; // tokens per second
  lastRefill: number;
}

const limiters = new Map<string, RateLimiter>();

export function createLimiter(id: string, maxTokens: number, refillRate: number): RateLimiter {
  const limiter: RateLimiter = { id, maxTokens, tokens: maxTokens, refillRate, lastRefill: Date.now() };
  limiters.set(id, limiter);
  return limiter;
}

function refill(limiter: RateLimiter): void {
  const now = Date.now();
  const elapsed = (now - limiter.lastRefill) / 1000;
  limiter.tokens = Math.min(limiter.maxTokens, limiter.tokens + elapsed * limiter.refillRate);
  limiter.lastRefill = now;
}

export function tryConsume(id: string, tokens = 1): boolean {
  const limiter = limiters.get(id);
  if (!limiter) return true; // no limiter = allow
  refill(limiter);
  if (limiter.tokens >= tokens) {
    limiter.tokens -= tokens;
    return true;
  }
  return false;
}

export function adaptLimit(id: string, factor: number): void {
  const limiter = limiters.get(id);
  if (limiter) {
    limiter.maxTokens = Math.max(1, Math.round(limiter.maxTokens * factor));
    limiter.refillRate = Math.max(0.1, limiter.refillRate * factor);
  }
}

export function getLimiter(id: string): RateLimiter | null {
  const l = limiters.get(id);
  if (l) refill(l);
  return l ?? null;
}

export function listLimiters(): RateLimiter[] { return [...limiters.values()]; }
