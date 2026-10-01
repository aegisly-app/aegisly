// Aegisly core: pure, dependency-free governance logic (runs on Workers and Node).

export const PLANS = {
  free:     { name: 'Free',     priceUsd: 0,   monthlyRequests: 1000,   maxKeys: 3,   retentionDays: 7 },
  team:     { name: 'Team',     priceUsd: 49,  monthlyRequests: 50000,  maxKeys: 25,  retentionDays: 90 },
  business: { name: 'Business', priceUsd: 299, monthlyRequests: 500000, maxKeys: 500, retentionDays: 365 },
};

// Estimated cost per 1K tokens charged to the workspace's internal budget (USD).
export const MODELS = {
  '@cf/meta/llama-3.2-3b-instruct': { label: 'Llama 3.2 3B', usdPer1kTokens: 0.0002 },
  '@cf/meta/llama-3.1-8b-instruct-fp8': { label: 'Llama 3.1 8B', usdPer1kTokens: 0.0003 },
  '@cf/mistralai/mistral-small-3.1-24b-instruct': { label: 'Mistral Small 3.1 24B', usdPer1kTokens: 0.0009 },
};
export const DEFAULT_MODEL = '@cf/meta/llama-3.2-3b-instruct';

export const DEFAULT_POLICY = {
  piiMode: 'redact',            // 'redact' | 'block' | 'off'
  secretsMode: 'block',         // secrets (API keys, private keys) are blocked by default
  blockedTerms: [],             // case-insensitive phrases that block the request
  maxPromptChars: 8000,
  allowedModels: Object.keys(MODELS),
  scanOutput: true,
};

function luhn(num) {
  const d = num.replace(/\D/g, '');
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

function validCpf(raw) {
  const c = raw.replace(/\D/g, '');
  if (c.length !== 11 || /^(\d)\1{10}$/.test(c)) return false;
  for (const len of [9, 10]) {
    let s = 0;
    for (let i = 0; i < len; i++) s += (c.charCodeAt(i) - 48) * (len + 1 - i);
    const dv = ((s * 10) % 11) % 10;
    if (dv !== c.charCodeAt(len) - 48) return false;
  }
  return true;
}

// Detector catalogue. `kind` groups findings into PII vs secrets for policy decisions.
export const DETECTORS = [
  { type: 'EMAIL', kind: 'pii', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  { type: 'CREDIT_CARD', kind: 'pii', re: /\b\d(?:[ -]?\d){12,18}\b/g, check: luhn },
  { type: 'US_SSN', kind: 'pii', re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  { type: 'BR_CPF', kind: 'pii', re: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g, check: validCpf },
  { type: 'IBAN', kind: 'pii', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b/g },
  { type: 'PHONE', kind: 'pii', re: /(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\b\d{2,4}[ .-])\d{3,5}[ .-]?\d{4}\b/g },
  { type: 'IP_ADDRESS', kind: 'pii', re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
  { type: 'AWS_ACCESS_KEY', kind: 'secret', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: 'API_KEY', kind: 'secret', re: /\b(?:sk|pk|rk)[-_](?:live|test|proj)?[-_]?[A-Za-z0-9]{20,}\b/g },
  { type: 'GITHUB_TOKEN', kind: 'secret', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { type: 'PRIVATE_KEY', kind: 'secret', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g },
  { type: 'JWT', kind: 'secret', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
];

/** Scan text and return non-overlapping findings sorted by position. */
export function scan(text) {
  const found = [];
  for (const d of DETECTORS) {
    d.re.lastIndex = 0;
    let m;
    while ((m = d.re.exec(text)) !== null) {
      const value = m[0];
      if (d.check && !d.check(value)) continue;
      found.push({ type: d.type, kind: d.kind, start: m.index, end: m.index + value.length });
    }
  }
  // Earlier start wins; on ties the longer match wins (secrets/cards before phones, etc).
  found.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const out = [];
  let lastEnd = -1;
  for (const f of found) {
    if (f.start >= lastEnd) { out.push(f); lastEnd = f.end; }
  }
  return out;
}

export function redact(text, findings) {
  let res = '', pos = 0;
  const counters = {};
  for (const f of findings) {
    counters[f.type] = (counters[f.type] || 0) + 1;
    res += text.slice(pos, f.start) + `[${f.type}_${counters[f.type]}]`;
    pos = f.end;
  }
  return res + text.slice(pos);
}

export function summarize(findings) {
  const s = {};
  for (const f of findings) s[f.type] = (s[f.type] || 0) + 1;
  return s;
}

/**
 * Evaluate a request against a workspace policy.
 * Returns { decision: 'allow'|'redact'|'block', reasons: [], messages, findings }.
 */
export function evaluate(messages, policyIn, model) {
  const policy = { ...DEFAULT_POLICY, ...(policyIn || {}) };
  const reasons = [];
  const allFindings = [];
  let decision = 'allow';
  const block = (r) => { decision = 'block'; reasons.push(r); };

  if (!Array.isArray(messages) || messages.length === 0) {
    return { decision: 'block', reasons: ['invalid_request: messages must be a non-empty array'], messages: [], findings: [] };
  }
  if (model && !policy.allowedModels.includes(model)) block(`model_not_allowed: ${model}`);

  const totalChars = messages.reduce((n, m) => n + String(m.content || '').length, 0);
  if (totalChars > policy.maxPromptChars) block(`prompt_too_long: ${totalChars} > ${policy.maxPromptChars}`);

  const out = messages.map((m) => {
    const content = String(m.content || '');
    const lower = content.toLowerCase();
    for (const t of policy.blockedTerms) {
      if (t && lower.includes(String(t).toLowerCase())) block(`blocked_term: "${t}"`);
    }
    const findings = scan(content);
    allFindings.push(...findings);
    const toRedact = findings.filter((f) =>
      (f.kind === 'pii' && policy.piiMode === 'redact') || (f.kind === 'secret' && policy.secretsMode === 'redact'));
    if (findings.some((f) => f.kind === 'pii') && policy.piiMode === 'block') block('pii_detected');
    if (findings.some((f) => f.kind === 'secret') && policy.secretsMode === 'block') block('secret_detected');
    return { role: m.role || 'user', content: toRedact.length ? redact(content, toRedact) : content };
  });

  if (decision !== 'block' && out.some((m, i) => m.content !== String(messages[i].content || ''))) {
    decision = 'redact';
    reasons.push('sensitive_data_redacted');
  }
  return { decision, reasons, messages: out, findings: summarize(allFindings) };
}

export function estimateTokens(text) {
  return Math.ceil(String(text || '').length / 4);
}

export function estimateCostUsd(model, tokens) {
  const m = MODELS[model] || MODELS[DEFAULT_MODEL];
  return +(tokens / 1000 * m.usdPer1kTokens).toFixed(6);
}

export async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomToken(prefix) {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const b = [...bytes].map((x) => x.toString(16).padStart(2, '0')).join('');
  return `${prefix}_${b}`;
}

/** Canonical string for an audit record; the chain hash covers every governed field. */
export function auditCanonical(r) {
  return [r.workspace_id, r.seq, r.ts, r.key_id, r.model, r.decision, r.reasons, r.findings,
    r.prompt_hash, r.tokens, r.cost_usd, r.prev_hash].join('|');
}

export function monthKey(date = new Date()) {
  return date.toISOString().slice(0, 7);
}
