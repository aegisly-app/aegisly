// End-to-end tests: node --no-warnings test/run.mjs
import assert from 'node:assert/strict';
import { createD1 } from './d1shim.mjs';
import { handleApi } from '../src/api.js';
import { scan, evaluate } from '../src/core.js';

let passed = 0;
const t = async (name, fn) => { await fn(); passed++; console.log('  ok -', name); };
const env = { DB: createD1(new URL('../schema.sql', import.meta.url)) };
const call = async (method, path, token, body) => {
  const res = await handleApi(new Request(`https://test.local${path}`, {
    method, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  }), env);
  const ct = res.headers.get('content-type') || '';
  return { status: res.status, headers: res.headers, body: ct.includes('json') ? await res.json() : await res.text() };
};

console.log('core');
await t('detects email, card (Luhn), phone, CPF, secrets', () => {
  const types = scan('mail a@b.co card 4242 4242 4242 4242 tel +1 415 555 0132 cpf 529.982.247-25 key sk-live-9fA8b7C6d5E4f3G2h1J0kLmNoPq AKIAABCDEFGHIJKLMNOP').map((f) => f.type);
  for (const x of ['EMAIL', 'CREDIT_CARD', 'PHONE', 'BR_CPF', 'API_KEY', 'AWS_ACCESS_KEY']) assert.ok(types.includes(x), x);
});
await t('rejects invalid card and invalid CPF', () => {
  const types = scan('order 1234 5678 9012 3456 and 111.111.111-11').map((f) => f.type);
  assert.ok(!types.includes('CREDIT_CARD')); assert.ok(!types.includes('BR_CPF'));
});
await t('redact policy rewrites, block policy blocks', () => {
  const r = evaluate([{ role: 'user', content: 'email me at x@y.com' }], { piiMode: 'redact' });
  assert.equal(r.decision, 'redact'); assert.match(r.messages[0].content, /\[EMAIL_1\]/);
  assert.equal(evaluate([{ role: 'user', content: 'x@y.com' }], { piiMode: 'block' }).decision, 'block');
  assert.equal(evaluate([{ role: 'user', content: 'ghp_' + 'a'.repeat(36) }], {}).decision, 'block');
  assert.equal(evaluate([{ role: 'user', content: 'About Project Falcon' }], { blockedTerms: ['project falcon'] }).decision, 'block');
});

console.log('api');
let admin, member;
await t('signup returns keys once; stores only hashes', async () => {
  const r = await call('POST', '/api/signup', null, { workspace: 'Acme', email: 'ops@acme.io' });
  assert.equal(r.status, 201); admin = r.body.admin_key; member = r.body.member_key;
  const row = env.DB._raw.prepare('SELECT key_hash FROM api_keys').all();
  assert.ok(row.every((x) => x.key_hash.length === 64 && x.key_hash !== admin && x.key_hash !== member));
});
await t('member key cannot use admin endpoints', async () => {
  assert.equal((await call('GET', '/api/me', member)).status, 403);
  assert.equal((await call('GET', '/api/me', 'nope')).status, 401);
});
await t('gateway redacts PII before the model and audits it', async () => {
  const r = await call('POST', '/api/v1/chat', member, { messages: [{ role: 'user', content: 'Customer jane@acme.io paid with 4242 4242 4242 4242' }] });
  assert.equal(r.status, 200); assert.equal(r.body.decision, 'redact');
  assert.ok(!JSON.stringify(r.body.sent_to_model).includes('jane@acme.io'));
  assert.equal(r.headers.get('x-aegisly-decision'), 'redact');
});
await t('gateway blocks secrets with 403 and still audits', async () => {
  const r = await call('POST', '/api/v1/chat', member, { messages: [{ role: 'user', content: 'use AKIAABCDEFGHIJKLMNOP' }] });
  assert.equal(r.status, 403); assert.deepEqual(r.body.error.reasons, ['secret_detected']);
});
await t('policy update applies to the gateway', async () => {
  const p = await call('PUT', '/api/policy', admin, { blockedTerms: ['merger'], piiMode: 'block' });
  assert.equal(p.status, 200);
  assert.equal((await call('POST', '/api/v1/chat', member, { messages: [{ role: 'user', content: 'Draft the merger memo' }] })).status, 403);
  await call('PUT', '/api/policy', admin, { blockedTerms: [], piiMode: 'redact' });
});
await t('audit chain verifies, and detects tampering', async () => {
  let v = await call('GET', '/api/audit/verify', admin);
  assert.equal(v.body.valid, true); assert.equal(v.body.checked, 3);
  env.DB._raw.exec("UPDATE audit_log SET decision = 'allow' WHERE seq = 2");
  v = await call('GET', '/api/audit/verify', admin);
  assert.equal(v.body.valid, false); assert.equal(v.body.broken_at_seq, 2);
  env.DB._raw.exec("UPDATE audit_log SET decision = 'block' WHERE seq = 2");
  assert.equal((await call('GET', '/api/audit/verify', admin)).body.valid, true);
});
await t('CSV export contains every audit row', async () => {
  const r = await call('GET', '/api/audit/export.csv', admin);
  assert.equal(r.body.trim().split('\n').length, 4);
});
await t('plan key limit enforced, sandbox upgrade lifts it', async () => {
  const ok = await call('POST', '/api/keys', admin, { label: 'Extra' });
  assert.equal(ok.status, 201);
  const over = await call('POST', '/api/keys', admin, { label: 'Too many' });
  assert.equal(over.status, 402);
  const up = await call('POST', '/api/billing/checkout', admin, { plan: 'team' });
  assert.equal(up.body.provider, 'sandbox');
  assert.equal((await call('POST', '/api/keys', admin, { label: 'Now fine' })).status, 201);
  assert.equal((await call('GET', '/api/me', admin)).body.workspace.plan, 'team');
});
await t('revoked key stops working', async () => {
  const k = await call('POST', '/api/keys', admin, { label: 'Temp' });
  await call('DELETE', `/api/keys/${k.body.id}`, admin);
  assert.equal((await call('POST', '/api/v1/chat', k.body.key, { messages: [{ role: 'user', content: 'hi' }] })).status, 401);
});
await t('per-key budget enforced', async () => {
  const k = await call('POST', '/api/keys', admin, { label: 'Tiny', monthly_budget_usd: 0 });
  assert.equal((await call('POST', '/api/v1/chat', k.body.key, { messages: [{ role: 'user', content: 'hi' }] })).status, 429);
});
await t('demo workspace seeds traffic through the real pipeline', async () => {
  const d = await call('POST', '/api/demo');
  assert.equal(d.status, 201);
  const a = await call('GET', '/api/audit', d.body.admin_key);
  assert.equal(a.body.entries.length, 6);
  assert.ok(a.body.entries.some((e) => e.decision === 'block') && a.body.entries.some((e) => e.decision === 'redact'));
  assert.equal((await call('GET', '/api/audit/verify', d.body.admin_key)).body.valid, true);
});
console.log(`\n${passed} tests passed`);
