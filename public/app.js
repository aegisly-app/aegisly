// Aegisly dashboard (vanilla JS, no build step).
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const ls = {
  get: (k) => { try { return localStorage.getItem(k); } catch (e) { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) {} },
  del: (k) => { try { localStorage.removeItem(k); } catch (e) {} },
};
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const money = (n) => { const v = Number(n || 0); return '$' + (v > 0 && v < 0.01 ? v.toFixed(6) : v.toFixed(2)); };
const fmt = (n) => Number(n || 0).toLocaleString('en-US');
let ME = null;

function toast(msg) {
  const d = document.createElement('div'); d.className = 'toast'; d.textContent = msg;
  document.body.appendChild(d); setTimeout(() => d.remove(), 4500);
}

async function api(path, opts = {}, token) {
  const r = await fetch(path, {
    ...opts,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token || ls.get('aegisly_admin')}`, ...(opts.headers || {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  return { ok: r.ok, status: r.status, data };
}

function tab(name) {
  $$('.side button').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  $$('[data-pane]').forEach((p) => p.classList.toggle('hidden', p.dataset.pane !== name));
  ({ overview: loadOverview, keys: loadKeys, audit: loadAudit, policy: loadPolicy, billing: loadBilling }[name] || (() => {}))();
}

const tag = (d) => `<span class="tag ${esc(d)}">${esc(d)}</span>`;
const findingsTxt = (f) => {
  try {
    const o = typeof f === 'string' ? JSON.parse(f) : f;
    const all = { ...(o.input || {}) };
    for (const [k, v] of Object.entries(o.output || {})) all[k + ' (out)'] = v;
    const s = Object.entries(all).map(([k, v]) => `${k}×${v}`).join(', ');
    return s || '—';
  } catch (e) { return '—'; }
};
const reasonsTxt = (r) => { try { return JSON.parse(r).join(', ') || '—'; } catch (e) { return '—'; } };

function auditRows(entries, full) {
  const head = `<tr><th>#</th><th>Time (UTC)</th><th>Key</th><th>Decision</th><th>Findings</th>${full ? '<th>Reasons</th><th>Tokens</th><th>Cost</th><th>Hash</th>' : ''}</tr>`;
  if (!entries.length) return head + `<tr><td colspan="9" style="color:var(--muted)">No requests yet. Try the Playground.</td></tr>`;
  return head + entries.map((e) => `<tr><td>${e.seq}</td><td class="mono">${esc(e.ts.replace('T', ' ').slice(0, 19))}</td><td>${esc(e.key_label || e.key_id)}</td><td>${tag(e.decision)}</td><td>${esc(findingsTxt(e.findings))}</td>${full ? `<td>${esc(reasonsTxt(e.reasons))}</td><td>${fmt(e.tokens)}</td><td>${money(e.cost_usd)}</td><td class="mono" title="prev ${esc(e.prev_hash)}">${esc(e.hash.slice(0, 12))}…</td>` : ''}</tr>`).join('');
}

async function loadMe() {
  const r = await api('/api/me');
  if (!r.ok) return false;
  ME = r.data;
  $('#wsName').textContent = `${ME.workspace.name} · ${ME.plan.name}`;
  return true;
}

async function loadOverview() {
  await loadMe();
  const u = ME.usage;
  $('#ovSub').textContent = `Workspace ${ME.workspace.name} — ${u.month}`;
  const cards = [['Requests', fmt(u.requests)], ['Redacted', fmt(u.redacted)], ['Blocked', fmt(u.blocked)], ['Est. model spend', money(u.cost_usd)]];
  $('#stats').innerHTML = cards.map(([l, v]) => `<div class="card stat"><div class="v">${v}</div><div class="l">${l}</div></div>`).join('');
  const pct = Math.min(100, (u.requests / ME.plan.monthlyRequests) * 100);
  $('#quotaTxt').textContent = `${fmt(u.requests)} of ${fmt(ME.plan.monthlyRequests)} requests on the ${ME.plan.name} plan`;
  $('#quotaBar').style.width = pct.toFixed(1) + '%';
  const a = await api('/api/audit?limit=8');
  $('#ovAudit').innerHTML = auditRows(a.data.entries || [], false);
}

async function loadPolicy() {
  await loadMe();
  const p = ME.policy;
  $('#poPii').value = p.piiMode; $('#poSec').value = p.secretsMode;
  $('#poTerms').value = (p.blockedTerms || []).join('\n'); $('#poMax').value = p.maxPromptChars; $('#poOut').checked = !!p.scanOutput;
}

async function loadKeys() {
  const r = await api('/api/keys');
  const rows = r.data.keys || [];
  $('#kTable').innerHTML = `<tr><th>Label</th><th>Role</th><th>Prefix</th><th>Budget</th><th>Requests</th><th>Blocked</th><th>Spend</th><th></th></tr>` +
    rows.map((k) => `<tr style="${k.revoked ? 'opacity:.45' : ''}"><td>${esc(k.label)}</td><td>${esc(k.role)}</td><td class="mono">${esc(k.key_prefix)}…</td><td>${k.monthly_budget_usd == null ? '—' : '$' + k.monthly_budget_usd}</td><td>${fmt(k.requests)}</td><td>${fmt(k.blocked)}</td><td>${money(k.cost_usd)}</td><td>${k.revoked ? 'revoked' : k.role === 'admin' ? '' : `<button class="btn small danger" data-revoke="${esc(k.id)}">Revoke</button>`}</td></tr>`).join('');
}

async function loadAudit() {
  const r = await api('/api/audit?limit=200');
  $('#auTable').innerHTML = auditRows(r.data.entries || [], true);
}

async function loadBilling() {
  await loadMe();
  $('#biSub').textContent = `Current plan: ${ME.plan.name}.` + (ME.billing_mode === 'sandbox' ? ' Billing is in sandbox mode on this deployment: plan changes are free and recorded as $0 events.' : ' Payments are processed by Stripe Checkout.');
  $('#biPlans').innerHTML = Object.entries(ME.plans).map(([id, p]) => `<div class="card price ${id === ME.workspace.plan ? 'featured' : ''}"><h3>${p.name}</h3><div class="amt">$${p.priceUsd}<small> / month</small></div><ul><li>${fmt(p.monthlyRequests)} requests / month</li><li>${p.maxKeys} active keys</li><li>${p.retentionDays}-day audit retention</li></ul>${id === ME.workspace.plan ? '<button class="btn" disabled>Current plan</button>' : `<button class="btn primary" data-plan="${id}">Switch to ${p.name}</button>`}</div>`).join('');
}

async function boot() {
  const qs = new URLSearchParams(location.search);
  if (!ls.get('aegisly_admin') || !(await loadMe())) {
    $('#login').classList.remove('hidden');
    return;
  }
  $('#shell').classList.remove('hidden');
  if (qs.get('welcome') || qs.get('demo')) {
    const n = $('#keysNotice');
    n.innerHTML = `${qs.get('demo') ? '<b>Sandbox workspace</b> pre-filled with sample traffic. ' : '<b>Workspace created.</b> '}Save your keys — they are never shown again.<br>Admin: <code>${esc(ls.get('aegisly_admin'))}</code><br>Member: <code>${esc(ls.get('aegisly_member') || '')}</code>`;
    n.classList.remove('hidden');
    history.replaceState(null, '', '/app.html');
  }
  if (qs.get('billing') === 'success') toast('Payment received. Your plan will update in a few seconds.');
  $('#pgModel').innerHTML = Object.entries(ME.models).map(([id, m]) => `<option value="${esc(id)}">${esc(m.label)}</option>`).join('');
  tab('overview');
}

// ---------- events ----------
$$('.side button').forEach((b) => (b.onclick = () => tab(b.dataset.tab)));
$('#logout').onclick = (e) => { e.preventDefault(); ls.del('aegisly_admin'); ls.del('aegisly_member'); location.href = '/'; };
$('#loginBtn').onclick = async () => {
  ls.set('aegisly_admin', $('#keyIn').value.trim());
  if (await loadMe()) location.reload(); else toast('Invalid admin key');
};
$$('[data-ex]').forEach((b) => (b.onclick = () => { $('#pgText').value = b.dataset.ex; }));
$('#pgScan').onclick = async () => {
  const r = await api('/api/scan', { method: 'POST', body: { text: $('#pgText').value, model: $('#pgModel').value } });
  $('#pgDecision').innerHTML = `${tag(r.data.decision)}\n${esc((r.data.reasons || []).join('\n'))}\nfindings: ${esc(JSON.stringify(r.data.findings))}`;
  $('#pgSent').textContent = r.data.decision === 'block' ? '(nothing — request would be blocked)' : r.data.messages?.[0]?.content;
  $('#pgResp').textContent = '(dry run — model not called)';
};
$('#pgSend').onclick = async (e) => {
  const member = ls.get('aegisly_member') || ls.get('aegisly_admin');
  e.target.disabled = true; $('#pgResp').textContent = 'Calling model…';
  const r = await api('/api/v1/chat', { method: 'POST', body: { model: $('#pgModel').value, messages: [{ role: 'user', content: $('#pgText').value }] } }, member);
  e.target.disabled = false;
  const d = r.data;
  if (r.status === 403) {
    $('#pgDecision').innerHTML = `${tag('block')}\n${esc(d.error.reasons.join('\n'))}\naudit #${d.audit.seq}`;
    $('#pgSent').textContent = '(nothing — blocked before the model)'; $('#pgResp').textContent = '—';
  } else if (!r.ok) {
    $('#pgDecision').textContent = `${r.status}: ${d.error?.message}`; $('#pgSent').textContent = '—'; $('#pgResp').textContent = '—';
  } else {
    $('#pgDecision').innerHTML = `${tag(d.decision)}\n${esc(d.reasons.join('\n') || 'no sensitive data')}\nfindings: ${esc(findingsTxt(d.findings))}\naudit #${d.audit.seq} · ~${d.usage.estimated_tokens} tokens · ${money(d.usage.estimated_cost_usd)}`;
    $('#pgSent').textContent = d.sent_to_model.map((m) => m.content).join('\n');
    $('#pgResp').textContent = d.choices[0].message.content;
  }
};
$('#poSave').onclick = async () => {
  const body = { piiMode: $('#poPii').value, secretsMode: $('#poSec').value, blockedTerms: $('#poTerms').value.split('\n'), maxPromptChars: Number($('#poMax').value), scanOutput: $('#poOut').checked };
  const r = await api('/api/policy', { method: 'PUT', body });
  toast(r.ok ? 'Policy saved — active for the next request.' : 'Could not save policy');
};
$('#kAdd').onclick = async () => {
  const b = $('#kBudget').value;
  const r = await api('/api/keys', { method: 'POST', body: { label: $('#kLabel').value, monthly_budget_usd: b === '' ? undefined : Number(b) } });
  if (!r.ok) return toast(r.data.error?.message || 'Could not create key');
  const n = $('#keysNotice');
  n.innerHTML = `New key for <b>${esc($('#kLabel').value)}</b> (copy now, shown once):<br><code>${esc(r.data.key)}</code>`;
  n.classList.remove('hidden'); $('#kLabel').value = ''; $('#kBudget').value = '';
  loadKeys();
};
$('#kTable').onclick = async (e) => {
  const id = e.target.dataset?.revoke; if (!id) return;
  const r = await api(`/api/keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
  toast(r.ok ? 'Key revoked' : r.data.error?.message); loadKeys();
};
$('#auVerify').onclick = async () => {
  const r = await api('/api/audit/verify');
  $('#auResult').innerHTML = r.data.valid ? `<span class="tag allow">chain valid</span> ${r.data.checked} entries · head ${esc((r.data.head || '').slice(0, 16))}…` : `<span class="tag block">tampering detected</span> at entry #${r.data.broken_at_seq}`;
};
$('#auCsv').onclick = async () => {
  const r = await api('/api/audit/export.csv');
  const url = URL.createObjectURL(new Blob([r.data], { type: 'text/csv' }));
  const a = document.createElement('a'); a.href = url; a.download = 'aegisly-audit.csv'; a.click(); URL.revokeObjectURL(url);
};
$('#biPlans').onclick = async (e) => {
  const plan = e.target.dataset?.plan; if (!plan) return;
  e.target.disabled = true;
  const r = await api('/api/billing/checkout', { method: 'POST', body: { plan } });
  if (r.data.checkout_url) { location.href = r.data.checkout_url; return; }
  toast(r.ok ? r.data.note : r.data.error?.message); loadBilling();
};
boot();
