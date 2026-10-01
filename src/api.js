// Aegisly HTTP API. Framework-free; runs on Cloudflare Pages Functions / Workers (env.DB = D1, env.AI = Workers AI).
import {
  PLANS, MODELS, DEFAULT_MODEL, DEFAULT_POLICY, evaluate, scan, redact, summarize,
  estimateTokens, estimateCostUsd, sha256Hex, randomToken, auditCanonical, monthKey,
} from './core.js';

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...extra } });
const err = (status, code, message) => json({ error: { code, message } }, status);
const nowIso = () => new Date().toISOString();
const uid = (p) => `${p}_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;

async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}

async function authenticate(request, env, roles) {
  const h = request.headers.get('authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  if (!token) return { error: err(401, 'unauthorized', 'Missing Bearer token') };
  const hash = await sha256Hex(token);
  const key = await env.DB.prepare(
    'SELECT k.*, w.name AS ws_name, w.plan, w.policy, w.owner_email, w.created_at AS ws_created FROM api_keys k JOIN workspaces w ON w.id = k.workspace_id WHERE k.key_hash = ?'
  ).bind(hash).first();
  if (!key || key.revoked) return { error: err(401, 'unauthorized', 'Invalid or revoked key') };
  if (roles && !roles.includes(key.role)) return { error: err(403, 'forbidden', `This endpoint requires role: ${roles.join(' or ')}`) };
  return { key };
}

async function createKey(env, workspaceId, label, role, budget) {
  const token = randomToken(role === 'admin' ? 'agy_admin' : 'agy_live');
  const id = uid('key');
  await env.DB.prepare(
    'INSERT INTO api_keys (id, workspace_id, label, role, key_hash, key_prefix, monthly_budget_usd, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, workspaceId, label, role, await sha256Hex(token), token.slice(0, 14), budget ?? null, nowIso()).run();
  return { id, token };
}

async function appendAudit(env, rec) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const last = await env.DB.prepare('SELECT seq, hash FROM audit_log WHERE workspace_id = ? ORDER BY seq DESC LIMIT 1')
      .bind(rec.workspace_id).first();
    const row = { ...rec, seq: (last?.seq || 0) + 1, prev_hash: last?.hash || 'GENESIS' };
    row.hash = await sha256Hex(auditCanonical(row));
    try {
      await env.DB.prepare(
        'INSERT INTO audit_log (workspace_id, seq, ts, key_id, model, decision, reasons, findings, prompt_hash, tokens, cost_usd, latency_ms, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
      ).bind(row.workspace_id, row.seq, row.ts, row.key_id, row.model, row.decision, row.reasons, row.findings,
        row.prompt_hash, row.tokens, row.cost_usd, row.latency_ms, row.prev_hash, row.hash).run();
      return row;
    } catch (e) {
      if (!/UNIQUE|PRIMARY|constraint/i.test(String(e?.message))) throw e;
    }
  }
  throw new Error('audit_append_conflict');
}

async function bumpUsage(env, wsId, keyId, decision, tokens, cost) {
  await env.DB.prepare(
    `INSERT INTO usage_monthly (workspace_id, month, key_id, requests, blocked, redacted, tokens, cost_usd)
     VALUES (?, ?, ?, 1, ?, ?, ?, ?)
     ON CONFLICT(workspace_id, month, key_id) DO UPDATE SET
       requests = requests + 1, blocked = blocked + excluded.blocked, redacted = redacted + excluded.redacted,
       tokens = tokens + excluded.tokens, cost_usd = cost_usd + excluded.cost_usd`
  ).bind(wsId, monthKey(), keyId, decision === 'block' ? 1 : 0, decision === 'redact' ? 1 : 0, tokens, cost).run();
}

async function workspaceMonthUsage(env, wsId) {
  return (await env.DB.prepare(
    'SELECT COALESCE(SUM(requests),0) AS requests, COALESCE(SUM(blocked),0) AS blocked, COALESCE(SUM(redacted),0) AS redacted, COALESCE(SUM(tokens),0) AS tokens, COALESCE(SUM(cost_usd),0) AS cost_usd FROM usage_monthly WHERE workspace_id = ? AND month = ?'
  ).bind(wsId, monthKey()).first());
}

async function runModel(env, model, messages) {
  if (env.AI && typeof env.AI.run === 'function') {
    try {
      const r = await env.AI.run(model, { messages, max_tokens: 512 });
      const text = typeof r?.response === 'string' ? r.response : (r?.choices?.[0]?.message?.content ?? r?.result?.response ?? '');
      return { text: String(text), simulated: false };
    } catch (e) {
      return { text: '', simulated: false, error: String(e?.message || e).slice(0, 200) };
    }
  }
  const lastUser = [...messages].reverse().find((m) => m.role === 'user')?.content || '';
  return { text: `[simulated model — no AI binding] Received ${lastUser.length} chars: "${lastUser.slice(0, 160)}"`, simulated: true };
}

// ---------- handlers ----------

async function signup(request, env, opts = {}) {
  const body = (await readJson(request)) || {};
  const name = String(body.workspace || '').trim().slice(0, 80);
  const email = String(body.email || '').trim().toLowerCase().slice(0, 120);
  if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return err(400, 'invalid_input', 'workspace and a valid email are required');
  const id = uid('ws');
  await env.DB.prepare('INSERT INTO workspaces (id, name, owner_email, plan, policy, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(id, name, email, 'free', JSON.stringify(DEFAULT_POLICY), nowIso()).run();
  const admin = await createKey(env, id, 'Owner (dashboard)', 'admin', null);
  const member = await createKey(env, id, opts.memberLabel || 'Default app', 'member', 25);
  return json({ workspace_id: id, admin_key: admin.token, member_key: member.token,
    note: 'Store these keys now. Aegisly keeps only SHA-256 hashes and cannot show them again.' }, 201);
}

const DEMO_PROMPTS = [
  'Summarize this support ticket: customer Jane Roe (jane.roe@acme.io, +1 415 555 0132) says card 4242 4242 4242 4242 was charged twice.',
  'Write a friendly onboarding email for new hires at our design studio.',
  'Debug this: const client = new Client("sk-live-9fA8b7C6d5E4f3G2h1J0kLmNoPqRs") throws 401.',
  'Translate to Portuguese: our Q3 roadmap focuses on reliability and SSO.',
  'Draft a reply to the vendor about the pricing for project Falcon — confidential.',
  'Cliente CPF 529.982.247-25 pediu segunda via do boleto, escreva a resposta.',
];

async function createDemo(request, env) {
  const fake = new Request('https://x/api/signup', { method: 'POST', body: JSON.stringify({ workspace: 'Demo Co (sandbox)', email: 'demo@aegisly.dev' }) });
  const res = await signup(fake, env, { memberLabel: 'Support bot' });
  const data = await res.json();
  const policy = { ...DEFAULT_POLICY, blockedTerms: ['project falcon'] };
  await env.DB.prepare('UPDATE workspaces SET policy = ? WHERE id = ?').bind(JSON.stringify(policy), data.workspace_id).run();
  const mk = await createKey(env, data.workspace_id, 'Marketing copilot', 'member', 10);
  // Seed traffic through the real gateway pipeline (simulated model so seeding is instant and free).
  const seedEnv = { DB: env.DB };
  for (let i = 0; i < DEMO_PROMPTS.length; i++) {
    const token = i % 2 ? mk.token : data.member_key;
    const req = new Request('https://x/api/v1/chat', {
      method: 'POST', headers: { authorization: `Bearer ${token}` },
      body: JSON.stringify({ messages: [{ role: 'user', content: DEMO_PROMPTS[i] }] }),
    });
    await chat(req, seedEnv);
  }
  return json({ ...data, demo: true }, 201);
}

async function chat(request, env) {
  const t0 = Date.now();
  const a = await authenticate(request, env, ['member', 'admin']);
  if (a.error) return a.error;
  const k = a.key;
  const body = await readJson(request);
  if (!body) return err(400, 'invalid_json', 'Body must be JSON: { "messages": [...] }');
  const model = body.model || DEFAULT_MODEL;
  const plan = PLANS[k.plan] || PLANS.free;

  const usage = await workspaceMonthUsage(env, k.workspace_id);
  if (usage.requests >= plan.monthlyRequests) {
    return err(429, 'plan_quota_exceeded', `Monthly request quota of the ${plan.name} plan reached (${plan.monthlyRequests}). Upgrade to continue.`);
  }
  if (k.monthly_budget_usd != null) {
    const ku = await env.DB.prepare('SELECT cost_usd FROM usage_monthly WHERE workspace_id = ? AND month = ? AND key_id = ?')
      .bind(k.workspace_id, monthKey(), k.id).first();
    if ((ku?.cost_usd || 0) >= k.monthly_budget_usd) return err(429, 'key_budget_exceeded', `Key budget of $${k.monthly_budget_usd} reached this month.`);
  }

  const policy = { ...DEFAULT_POLICY, ...JSON.parse(k.policy || '{}') };
  const ev = evaluate(body.messages, policy, model);
  const promptText = Array.isArray(body.messages) ? body.messages.map((m) => String(m?.content || '')).join('\n') : '';
  const promptHash = await sha256Hex(promptText);

  let output = null, simulated = false, outputFindings = {};
  let tokens = estimateTokens(promptText);
  if (ev.decision !== 'block') {
    const r = await runModel(env, model, ev.messages);
    simulated = r.simulated;
    if (r.error) return err(502, 'model_error', `Model call failed: ${r.error}`);
    output = r.text;
    if (policy.scanOutput) {
      const f = scan(output).filter((x) => x.kind === 'secret' || policy.piiMode !== 'off');
      if (f.length) { output = redact(output, f); outputFindings = summarize(f); }
    }
    tokens += estimateTokens(output);
  }
  const cost = ev.decision === 'block' ? 0 : estimateCostUsd(model, tokens);
  const findings = { input: ev.findings, output: outputFindings };
  const rec = await appendAudit(env, {
    workspace_id: k.workspace_id, ts: nowIso(), key_id: k.id, model, decision: ev.decision,
    reasons: JSON.stringify(ev.reasons), findings: JSON.stringify(findings), prompt_hash: promptHash,
    tokens: ev.decision === 'block' ? 0 : tokens, cost_usd: cost, latency_ms: Date.now() - t0,
  });
  await bumpUsage(env, k.workspace_id, k.id, ev.decision, ev.decision === 'block' ? 0 : tokens, cost);

  const headers = { 'x-aegisly-decision': ev.decision, 'x-aegisly-audit-seq': String(rec.seq) };
  if (ev.decision === 'block') {
    return json({ error: { code: 'policy_violation', message: 'Request blocked by workspace policy', reasons: ev.reasons }, findings, audit: { seq: rec.seq, hash: rec.hash } }, 403, headers);
  }
  return json({
    model, decision: ev.decision, reasons: ev.reasons, findings, simulated,
    sent_to_model: ev.messages,
    choices: [{ index: 0, message: { role: 'assistant', content: output } }],
    usage: { estimated_tokens: tokens, estimated_cost_usd: cost },
    audit: { seq: rec.seq, hash: rec.hash },
  }, 200, headers);
}

async function me(request, env) {
  const a = await authenticate(request, env, ['admin']);
  if (a.error) return a.error;
  const k = a.key;
  const usage = await workspaceMonthUsage(env, k.workspace_id);
  return json({
    workspace: { id: k.workspace_id, name: k.ws_name, owner_email: k.owner_email, plan: k.plan, created_at: k.ws_created },
    plan: PLANS[k.plan], plans: PLANS, policy: { ...DEFAULT_POLICY, ...JSON.parse(k.policy || '{}') },
    usage: { month: monthKey(), ...usage }, models: MODELS,
    billing_mode: env.STRIPE_SECRET_KEY ? 'stripe' : 'sandbox',
  });
}

async function updatePolicy(request, env) {
  const a = await authenticate(request, env, ['admin']);
  if (a.error) return a.error;
  const b = (await readJson(request)) || {};
  const p = { ...DEFAULT_POLICY, ...JSON.parse(a.key.policy || '{}') };
  if (['redact', 'block', 'off'].includes(b.piiMode)) p.piiMode = b.piiMode;
  if (['redact', 'block', 'off'].includes(b.secretsMode)) p.secretsMode = b.secretsMode;
  if (Array.isArray(b.blockedTerms)) p.blockedTerms = b.blockedTerms.map((t) => String(t).trim()).filter(Boolean).slice(0, 100);
  if (Number.isFinite(b.maxPromptChars)) p.maxPromptChars = Math.max(100, Math.min(100000, Math.floor(b.maxPromptChars)));
  if (Array.isArray(b.allowedModels)) p.allowedModels = b.allowedModels.filter((m) => MODELS[m]);
  if (typeof b.scanOutput === 'boolean') p.scanOutput = b.scanOutput;
  await env.DB.prepare('UPDATE workspaces SET policy = ? WHERE id = ?').bind(JSON.stringify(p), a.key.workspace_id).run();
  return json({ policy: p });
}

async function listKeys(request, env) {
  const a = await authenticate(request, env, ['admin']);
  if (a.error) return a.error;
  const { results } = await env.DB.prepare(
    `SELECT k.id, k.label, k.role, k.key_prefix, k.monthly_budget_usd, k.revoked, k.created_at,
            COALESCE(u.requests,0) AS requests, COALESCE(u.blocked,0) AS blocked, COALESCE(u.redacted,0) AS redacted, COALESCE(u.cost_usd,0) AS cost_usd
     FROM api_keys k LEFT JOIN usage_monthly u ON u.key_id = k.id AND u.month = ?
     WHERE k.workspace_id = ? ORDER BY k.created_at`
  ).bind(monthKey(), a.key.workspace_id).all();
  return json({ keys: results });
}

async function addKey(request, env) {
  const a = await authenticate(request, env, ['admin']);
  if (a.error) return a.error;
  const b = (await readJson(request)) || {};
  const label = String(b.label || '').trim().slice(0, 60);
  if (!label) return err(400, 'invalid_input', 'label is required');
  const plan = PLANS[a.key.plan] || PLANS.free;
  const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM api_keys WHERE workspace_id = ? AND revoked = 0').bind(a.key.workspace_id).first();
  if (c.n >= plan.maxKeys) return err(402, 'plan_limit', `The ${plan.name} plan allows ${plan.maxKeys} active keys. Upgrade to add more.`);
  const budget = Number.isFinite(b.monthly_budget_usd) ? Math.max(0, b.monthly_budget_usd) : null;
  const k = await createKey(env, a.key.workspace_id, label, 'member', budget);
  return json({ id: k.id, key: k.token, note: 'Copy this key now; it will not be shown again.' }, 201);
}

async function revokeKey(request, env, id) {
  const a = await authenticate(request, env, ['admin']);
  if (a.error) return a.error;
  if (id === a.key.id) return err(400, 'invalid_input', 'You cannot revoke the key you are using');
  const r = await env.DB.prepare('UPDATE api_keys SET revoked = 1 WHERE id = ? AND workspace_id = ?').bind(id, a.key.workspace_id).run();
  if (!r.meta?.changes) return err(404, 'not_found', 'Key not found');
  return json({ revoked: id });
}

async function dryRun(request, env) {
  const a = await authenticate(request, env, ['admin']);
  if (a.error) return a.error;
  const b = (await readJson(request)) || {};
  const policy = { ...DEFAULT_POLICY, ...JSON.parse(a.key.policy || '{}') };
  return json(evaluate([{ role: 'user', content: String(b.text || '') }], policy, b.model || DEFAULT_MODEL));
}

async function audit(request, env, url) {
  const a = await authenticate(request, env, ['admin']);
  if (a.error) return a.error;
  const limit = Math.min(500, Math.max(1, parseInt(url.searchParams.get('limit') || '50', 10)));
  const { results } = await env.DB.prepare(
    'SELECT a.*, k.label AS key_label FROM audit_log a LEFT JOIN api_keys k ON k.id = a.key_id WHERE a.workspace_id = ? ORDER BY a.seq DESC LIMIT ?'
  ).bind(a.key.workspace_id, limit).all();
  return json({ entries: results });
}

async function auditCsv(request, env) {
  const a = await authenticate(request, env, ['admin']);
  if (a.error) return a.error;
  const { results } = await env.DB.prepare('SELECT * FROM audit_log WHERE workspace_id = ? ORDER BY seq').bind(a.key.workspace_id).all();
  const cols = ['seq', 'ts', 'key_id', 'model', 'decision', 'reasons', 'findings', 'prompt_hash', 'tokens', 'cost_usd', 'latency_ms', 'prev_hash', 'hash'];
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const csv = [cols.join(','), ...results.map((r) => cols.map((c) => esc(r[c])).join(','))].join('\n');
  return new Response(csv, { headers: { 'content-type': 'text/csv; charset=utf-8', 'content-disposition': `attachment; filename="aegisly-audit-${a.key.workspace_id}.csv"` } });
}

async function verifyAudit(request, env) {
  const a = await authenticate(request, env, ['admin']);
  if (a.error) return a.error;
  const { results } = await env.DB.prepare('SELECT * FROM audit_log WHERE workspace_id = ? ORDER BY seq').bind(a.key.workspace_id).all();
  let prev = 'GENESIS';
  for (const r of results) {
    const expected = await sha256Hex(auditCanonical({ ...r, prev_hash: prev }));
    if (r.prev_hash !== prev || r.hash !== expected) {
      return json({ valid: false, checked: results.length, broken_at_seq: r.seq });
    }
    prev = r.hash;
  }
  return json({ valid: true, checked: results.length, head: prev });
}

async function checkout(request, env, url) {
  const a = await authenticate(request, env, ['admin']);
  if (a.error) return a.error;
  const b = (await readJson(request)) || {};
  const plan = String(b.plan || '');
  if (!PLANS[plan]) return err(400, 'invalid_input', 'Unknown plan');
  if (plan === a.key.plan) return err(400, 'invalid_input', 'Already on this plan');

  if (env.STRIPE_SECRET_KEY && env[`STRIPE_PRICE_${plan.toUpperCase()}`]) {
    const form = new URLSearchParams({
      mode: 'subscription',
      'line_items[0][price]': env[`STRIPE_PRICE_${plan.toUpperCase()}`],
      'line_items[0][quantity]': '1',
      client_reference_id: a.key.workspace_id,
      'metadata[plan]': plan,
      success_url: `${url.origin}/app.html?billing=success`,
      cancel_url: `${url.origin}/app.html?billing=cancel`,
    });
    const r = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST', body: form,
      headers: { authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, 'content-type': 'application/x-www-form-urlencoded' },
    });
    const s = await r.json();
    if (!r.ok) return err(502, 'billing_provider_error', s?.error?.message || 'Stripe error');
    return json({ provider: 'stripe', checkout_url: s.url });
  }
  // Sandbox billing: no payment processor configured, plan change is recorded as a $0 sandbox event.
  await env.DB.prepare('UPDATE workspaces SET plan = ? WHERE id = ?').bind(plan, a.key.workspace_id).run();
  await env.DB.prepare('INSERT INTO billing_events (id, workspace_id, ts, type, from_plan, to_plan, amount_usd, provider, reference) VALUES (?,?,?,?,?,?,?,?,?)')
    .bind(uid('bev'), a.key.workspace_id, nowIso(), 'plan_change', a.key.plan, plan, 0, 'sandbox', 'no charge').run();
  return json({ provider: 'sandbox', plan, note: 'Sandbox mode: plan switched without charge. Set STRIPE_SECRET_KEY and STRIPE_PRICE_* to enable real checkout.' });
}

async function stripeWebhook(request, env) {
  if (!env.STRIPE_WEBHOOK_SECRET) return err(404, 'not_found', 'Webhook not configured');
  const payload = await request.text();
  const sig = request.headers.get('stripe-signature') || '';
  const parts = Object.fromEntries(sig.split(',').map((p) => p.split('=')));
  if (!parts.t || !parts.v1 || Math.abs(Date.now() / 1000 - Number(parts.t)) > 300) return err(400, 'bad_signature', 'Invalid signature');
  const keyData = new TextEncoder().encode(env.STRIPE_WEBHOOK_SECRET);
  const k = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(`${parts.t}.${payload}`));
  const hex = [...new Uint8Array(mac)].map((x) => x.toString(16).padStart(2, '0')).join('');
  if (hex !== parts.v1) return err(400, 'bad_signature', 'Invalid signature');
  const evt = JSON.parse(payload);
  if (evt.type === 'checkout.session.completed') {
    const s = evt.data.object;
    const plan = s.metadata?.plan;
    if (PLANS[plan] && s.client_reference_id) {
      await env.DB.prepare('UPDATE workspaces SET plan = ? WHERE id = ?').bind(plan, s.client_reference_id).run();
      await env.DB.prepare('INSERT INTO billing_events (id, workspace_id, ts, type, from_plan, to_plan, amount_usd, provider, reference) VALUES (?,?,?,?,?,?,?,?,?)')
        .bind(uid('bev'), s.client_reference_id, nowIso(), 'subscription_started', null, plan, (s.amount_total || 0) / 100, 'stripe', s.id).run();
    }
  }
  return json({ received: true });
}

export async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '');
  const m = request.method;
  try {
    if (m === 'OPTIONS') return new Response(null, { status: 204, headers: { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type', 'access-control-allow-methods': 'GET, POST, PUT, DELETE' } });
    if (path === '/api/health') return await json({ ok: true, ai: !!env.AI, db: !!env.DB, ts: nowIso() });
    if (path === '/api/plans' && m === 'GET') return await json({ plans: PLANS, models: MODELS });
    if (path === '/api/signup' && m === 'POST') return await signup(request, env);
    if (path === '/api/demo' && m === 'POST') return await createDemo(request, env);
    if (path === '/api/v1/chat' && m === 'POST') return await chat(request, env);
    if (path === '/api/me' && m === 'GET') return await me(request, env);
    if (path === '/api/policy' && m === 'PUT') return await updatePolicy(request, env);
    if (path === '/api/keys' && m === 'GET') return await listKeys(request, env);
    if (path === '/api/keys' && m === 'POST') return await addKey(request, env);
    if (path.startsWith('/api/keys/') && m === 'DELETE') return await revokeKey(request, env, decodeURIComponent(path.slice(10)));
    if (path === '/api/scan' && m === 'POST') return await dryRun(request, env);
    if (path === '/api/audit' && m === 'GET') return await audit(request, env, url);
    if (path === '/api/audit/export.csv' && m === 'GET') return await auditCsv(request, env);
    if (path === '/api/audit/verify' && m === 'GET') return await verifyAudit(request, env);
    if (path === '/api/billing/checkout' && m === 'POST') return await checkout(request, env, url);
    if (path === '/api/billing/webhook' && m === 'POST') return await stripeWebhook(request, env);
    return err(404, 'not_found', `No route for ${m} ${path}`);
  } catch (e) {
    return err(500, 'internal_error', 'Unexpected error');
  }
}
