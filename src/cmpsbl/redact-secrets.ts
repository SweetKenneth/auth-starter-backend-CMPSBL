/**
 * BLDBL · PRM · redact-secrets
 * Reworked from: CMPSBL · src/lib/defense/redact.ts
 *
 * Secret masking for logs, UIs, and errors. Walks any value and redacts
 * sensitive keys, sensitive value shapes (JWT, API key prefixes, base64,
 * UUIDs), headers, URLs (query params + auth), and error objects.
 *
 * Free-text handling: the shape patterns below are anchored, so they only fire
 * when the WHOLE string is a secret. Log lines and stack traces almost never
 * look like that — the secret is embedded in prose ("auth failed for token
 * eyJhbG..."). Anchored-only matching therefore leaked embedded credentials
 * through `redactError` and reported `mightContainSecrets() === false`. The
 * unanchored EMBEDDED_SECRET_PATTERNS below scrub in-string occurrences too.
 *
 * Zero deps. Pure TS. Circular-ref + depth guarded.
 */

const SECRET_KEY_PATTERNS = [
  /^(OPENAI|GROQ|ANTHROPIC|PERPLEXITY|FIRECRAWL|E2B|SUPABASE|STRIPE|RESEND|CLERK|AUTH0)/i,
  /(_KEY|_SECRET|_TOKEN|_PASSWORD|_CREDENTIAL|_API_KEY|_PRIVATE)$/i,
  /^(api[_-]?key|secret|token|password|credential|authorization|bearer|jwt)$/i,
  /^(access[_-]?token|refresh[_-]?token|id[_-]?token)$/i,
  /^(private[_-]?key|public[_-]?key|signing[_-]?key)$/i,
  /^(database[_-]?url|connection[_-]?string|dsn)$/i,
  /^(cookie|session|auth)$/i,
];

const SECRET_VALUE_PATTERNS = [
  /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
  /^(sk-|pk-|clf-|rk_|ak_|key-|secret-)[A-Za-z0-9_-]{20,}$/,
  // Vendor credential shapes. Added after an adversarial pass showed AWS access
  // key ids, underscore-style Stripe keys and forge tokens surviving the scrub.
  /^(sk|pk|rk|whsec)_(live|test)_[A-Za-z0-9]{8,}$/,
  /^(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}$/,
  /^(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})$/,
  /^AIza[0-9A-Za-z_-]{30,}$/,
  /^xox[abprs]-[A-Za-z0-9-]{10,}$/,
  /^(glpat|glptt)-[A-Za-z0-9_-]{16,}$/,
  /^Bearer\s+[A-Za-z0-9_-]+/i,
  /^[A-Za-z0-9+/=]{40,}$/,
  /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i,
];

/**
 * Unanchored counterparts, deliberately narrower than the anchored set so
 * ordinary long identifiers in prose are not shredded. Each carries the `g`
 * flag; `scrubText` clones them per call to stay reentrant.
 */
const EMBEDDED_SECRET_PATTERNS: RegExp[] = [
  // JWT
  /eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g,
  // Provider-prefixed API keys
  /\b(?:sk|pk|clf)-[A-Za-z0-9_-]{20,}/g,
  /\b(?:rk_|ak_|key-|secret-)[A-Za-z0-9_-]{20,}/g,
  // Vendor credential shapes, unanchored. Same adversarial finding as above:
  // these appear inside prose ("stripe sk_live_...", "key=AKIA...").
  /\b(?:sk|pk|rk|whsec)_(?:live|test)_[A-Za-z0-9]{8,}/g,
  /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bAIza[0-9A-Za-z_-]{30,}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
  /\b(?:glpat|glptt)-[A-Za-z0-9_-]{16,}\b/g,
  // Bearer / Basic authorization values
  /\b(?:Bearer|Basic)\s+[A-Za-z0-9_\-.+/=]{12,}/gi,
  // key=value / key: value credential pairs in log lines
  /\b(?:api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|token|secret|password|passwd|pwd|signature|sig|credential|key)\b\s*[:=]\s*"?[^\s"'&,;)}\]]{6,}"?/gi,
  // Postgres / mongo / redis style connection strings with inline credentials
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s/@:]+:[^\s/@]+@/gi,
  // PEM private key blocks
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

const SENSITIVE_HEADERS = new Set([
  'authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token',
  'x-access-token', 'x-refresh-token', 'x-session-id', 'x-csrf-token',
  'proxy-authorization',
]);

const SENSITIVE_PARAMS = new Set([
  'token', 'api_key', 'apikey', 'key', 'secret', 'password',
  'access_token', 'refresh_token', 'auth', 'session', 'signature', 'sig',
]);

const REDACTED = '[REDACTED]';
const PARTIAL_MASK_LENGTH = 4;

function isSecretKey(key: string): boolean { return SECRET_KEY_PATTERNS.some(p => p.test(key)); }
function isSecretValue(value: string): boolean { return SECRET_VALUE_PATTERNS.some(p => p.test(value)); }

function maskValue(value: string, showPartial = false): string {
  if (!showPartial || value.length < PARTIAL_MASK_LENGTH * 2) return REDACTED;
  return `${value.slice(0, PARTIAL_MASK_LENGTH)}...${value.slice(-PARTIAL_MASK_LENGTH)}`;
}

/**
 * Replace secret-shaped substrings inside free text. Whole-string secrets are
 * handled by the anchored path first; this covers everything embedded in prose,
 * stack frames, and log lines.
 */
export function scrubText(text: string): string {
  if (!text) return text;
  let out = text;
  for (const pattern of EMBEDDED_SECRET_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    out = out.replace(re, match => {
      // Keep the credential's label so the log stays readable: `token=[REDACTED]`.
      const labelled = /^([A-Za-z0-9_-]+)\s*([:=])\s*/.exec(match);
      if (labelled) return `${labelled[1]}${labelled[2]}${REDACTED}`;
      const scheme = /^(Bearer|Basic)\s+/i.exec(match);
      if (scheme) return `${scheme[1]} ${REDACTED}`;
      const dsn = /^([a-z][a-z0-9+.-]*:\/\/)([^\s/@:]+):[^\s/@]+@$/i.exec(match);
      if (dsn) return `${dsn[1]}${dsn[2]}:${REDACTED}@`;
      return REDACTED;
    });
  }
  return out;
}

export function redactSecrets<T>(data: T, showPartial = false, _depth = 0, _seen?: WeakSet<object>): T {
  if (data === null || data === undefined) return data;
  if (_depth > 20) return REDACTED as T;
  if (typeof data === 'string') {
    return (isSecretValue(data) ? maskValue(data, showPartial) : scrubText(data)) as T;
  }
  if (typeof data !== 'object') return data;

  const seen = _seen ?? new WeakSet<object>();
  if (seen.has(data as object)) return REDACTED as T;
  seen.add(data as object);

  if (Array.isArray(data)) return data.map(i => redactSecrets(i, showPartial, _depth + 1, seen)) as T;

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    if (isSecretKey(key)) {
      result[key] = typeof value === 'string' ? maskValue(value, showPartial) : REDACTED;
    } else if (typeof value === 'string' && isSecretValue(value)) {
      result[key] = maskValue(value, showPartial);
    } else {
      result[key] = redactSecrets(value, showPartial, _depth + 1, seen);
    }
  }
  return result as T;
}

export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    result[key] = SENSITIVE_HEADERS.has(key.toLowerCase()) ? REDACTED : scrubText(value);
  }
  return result;
}

export function redactUrl(url: string): string {
  try {
    const parsed = new URL(url);
    for (const param of SENSITIVE_PARAMS) {
      if (parsed.searchParams.has(param)) parsed.searchParams.set(param, REDACTED);
    }
    for (const [key] of parsed.searchParams.entries()) {
      if (isSecretKey(key)) parsed.searchParams.set(key, REDACTED);
    }
    if (parsed.password) parsed.password = REDACTED;
    return parsed.toString();
  } catch {
    return url.replace(/([?&])(token|key|secret|password|api_key)=[^&]+/gi, `$1$2=${REDACTED}`);
  }
}

export function redactError(error: Error): { message: string; stack?: string } {
  return {
    message: redactSecrets(error.message) as string,
    stack: error.stack ? (redactSecrets(error.stack) as string) : undefined,
  };
}

export function mightContainSecrets(text: string): boolean {
  if (SECRET_VALUE_PATTERNS.some(p => p.test(text))) return true;
  return EMBEDDED_SECRET_PATTERNS.some(p => new RegExp(p.source, p.flags.replace('g', '')).test(text));
}
