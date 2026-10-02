# Aegisly — AI usage governance for teams

**Let your team use AI without leaking your customers.**
Aegisly is an AI gateway. It redacts personal data and secrets *before* they reach the model, enforces workspace policies, plan quotas and per-key budgets, and writes every call to a hash-chained audit log that anyone on the compliance team can verify.

- **Live demo:** https://aegisly.walter-bruno86.workers.dev. Click *Open live demo workspace* to get a sandbox with sample traffic.
- **API docs:** `/docs.html`
- Built for **Galuxium Nexus V2** (Devpost), October 2026.

---

## The problem

Employees paste support tickets, CRM exports and code into AI tools every day. Those prompts contain customer emails, card numbers, national IDs and API keys. Most small and mid-size companies have no visibility into this:

- Data leaves the company with every request (GDPR / LGPD / PCI exposure).
- Nobody can show an auditor what was sent, by which app, under which policy.
- Spend is untracked and unbounded per team.

Enterprise DLP suites solve this, but they cost five figures and take months to roll out. Aegisly is a drop-in endpoint that a team can adopt in an afternoon.

## What it does

| Capability | How |
|---|---|
| Pre-model redaction | 12 deterministic detectors. PII: email, phone, Luhn-validated cards, US SSN, Brazilian CPF (check digits), IBAN, IP. Secrets: AWS keys, `sk-/pk-/rk-` keys, GitHub tokens, JWTs, private keys. Values become placeholders such as `[EMAIL_1]`. |
| Policy engine | Per workspace: PII mode and secrets mode (`redact` / `block` / `off`), blocked confidential terms, max prompt size, allowed models, output scanning. Changes apply on the next request. |
| Output scanning | Model responses are scanned too, so leaked values cannot come back out. |
| Tamper-evident audit | Each entry stores `sha256(prompt)` (never the prompt), the decision, findings, tokens and cost. It also stores `prev_hash`, and `hash = sha256(canonical(entry) ‖ prev_hash)`. `GET /api/audit/verify` recomputes the chain and reports the first broken entry. CSV export is available for auditors. |
| Keys & budgets | Admin keys for the dashboard, member keys per app or team with optional monthly USD budgets, and instant revocation. Keys are stored only as SHA-256 hashes. |
| Usage & cost | Monthly requests, redactions, blocks, tokens and estimated spend per key and per workspace. |
| Plans & billing | Free / Team / Business limits are enforced server-side (keys, monthly requests). Stripe Checkout and signed webhook handling are included. Without Stripe credentials the deployment runs in clearly labelled sandbox billing. |

## Architecture

```
Browser (static dashboard, vanilla JS)        Customer app (any language)
            │  admin key                                  │  member key
            ▼                                             ▼
┌──────────────────── Cloudflare Worker (edge) ─────────────────────────────┐
│ src/worker.js → static assets │ /api/* → src/api.js (router, auth, billing)│
│                         └→ src/core.js (detectors, policy, hashing)       │
└──────────┬──────────────────────────────┬─────────────────────────────────┘
           │ D1 (SQLite)                  │ Workers AI binding
           ▼                              ▼
  workspaces · api_keys · audit_log   @cf/meta/llama-3.2-3b-instruct (default)
  usage_monthly · billing_events      @cf/meta/llama-3.1-8b-instruct-fp8
                                      @cf/mistralai/mistral-small-3.1-24b-instruct
```

Request pipeline for `POST /api/v1/chat`:

1. **Authenticate:** hash the bearer token and look it up in the key table, rejecting revoked keys.
2. **Check limits:** plan monthly quota (429), then the per-key budget (429).
3. **Evaluate policy:** model allow-list, size limit, blocked terms, detectors. The result is redact, block (403) or allow.
4. **Call the model:** Workers AI receives only the redacted messages.
5. **Scan the output** and redact it if needed.
6. **Append the audit entry** (hash chain) and update the monthly usage counters.
7. **Respond** with the decision, findings, what was sent to the model, usage and the audit pointer.

**Why this stack:** it runs on the edge in every region, has no servers to patch and costs nothing at prototype scale. All logic is plain ES modules with zero runtime dependencies, so the same code runs on Workers and in Node for tests.

## Database schema

See [`schema.sql`](schema.sql). Main tables:

- `workspaces(id, name, owner_email, plan, policy JSON, created_at)`
- `api_keys(id, workspace_id, label, role, key_hash UNIQUE, key_prefix, monthly_budget_usd, revoked, created_at)`
- `audit_log(workspace_id, seq, ts, key_id, model, decision, reasons, findings, prompt_hash, tokens, cost_usd, latency_ms, prev_hash, hash)`, primary key `(workspace_id, seq)`
- `usage_monthly(workspace_id, month, key_id, requests, blocked, redacted, tokens, cost_usd)`, upserted per request
- `billing_events(id, workspace_id, ts, type, from_plan, to_plan, amount_usd, provider, reference)`

## Monetization blueprint

| Plan | Price | Limits | Who |
|---|---|---|---|
| Free | $0 | 3 keys · 1,000 req/mo · 7-day retention | Evaluation, solo developers |
| Team | $49/mo | 25 keys · 50,000 req/mo · 90-day retention · per-key budgets | Startups and agencies of 5–50 people using AI in support, sales and engineering |
| Business | $299/mo | 500 keys · 500,000 req/mo · 1-year retention | Companies with compliance obligations (SOC 2, LGPD/GDPR, PCI) |

- **Revenue model:** recurring SaaS subscription through Stripe Checkout. A natural expansion is metered overage per 10K requests and an annual plan at a 2-month discount.
- **Unit economics (estimate):** Llama 3.2 3B on Workers AI is estimated at about $0.0002 per 1K tokens. A Team customer using its full 50K requests at ~600 tokens each (30M tokens) costs about $6/month in inference, roughly 88% gross margin at $49. Most customers will bring their own model provider in v2, which pushes margin above 90%.
- **Go-to-market:**
  - A free tier with the live playground, since the "see your data get redacted" moment sells the product.
  - SEO pages per regulation (LGPD + AI, PCI + AI).
  - Integrations for n8n, Zapier and LangChain.
  - Agencies that resell to their clients.
- **Moat over time:** policy templates per industry, signed audit exports accepted by auditors, and a detector library tuned with customer feedback.

## Governance & compliance by design

- Raw prompts are never persisted; only SHA-256 digests are stored.
- API keys are never persisted; only SHA-256 hashes are stored, and each key is shown once.
- Every decision is explainable (`reasons`, `findings`) and reproducible: detectors are deterministic, not a black-box model.
- The audit trail is tamper-evident (hash chain plus a verification endpoint).
- Least privilege: member keys can only call the gateway, and only admin keys manage the workspace.
- **Known limits (honest):** pattern detection does not catch names or free-text identifiers. Sandbox billing does not charge. The audit chain detects tampering but does not prevent a database administrator from rewriting the whole chain; anchoring the head hash externally is on the roadmap.

## Run locally

Requirements: Node.js ≥ 22.5 (uses the built-in `node:sqlite` for a local D1 shim). No `npm install` is needed.

```bash
node --no-warnings test/run.mjs        # 16 end-to-end tests (core + API)
node --no-warnings test/devserver.mjs  # http://localhost:8788 (model responses are simulated without Workers AI)
```

## Deploy (Cloudflare, free tier)

```bash
node build.mjs                                  # bundles src/ + public/ into dist/worker.js
npx wrangler d1 create aegisly                  # paste the database_id into wrangler.toml
npx wrangler d1 execute aegisly --remote --file=schema.sql
npx wrangler deploy                             # Worker with D1 + Workers AI bindings
```
The same code also runs as Cloudflare Pages Functions (`functions/api/[[path]].js` + `public/`).

Optional secrets for real billing: `STRIPE_SECRET_KEY`, `STRIPE_PRICE_TEAM`, `STRIPE_PRICE_BUSINESS`, `STRIPE_WEBHOOK_SECRET` (webhook URL: `/api/billing/webhook`).

## Repository layout

```
public/           landing page, dashboard (app.html/app.js), API docs, styles
src/worker.js     Worker entry (assets + API); build.mjs bundles it to dist/worker.js
functions/api/    alternative Pages Function entry → src/api.js
src/core.js       detectors, policy evaluation, hashing, plans (pure, dependency-free)
src/api.js        HTTP router, auth, quotas, gateway pipeline, audit chain, billing
schema.sql        D1 schema
test/             D1 shim, end-to-end tests, local dev server
```

## AI usage disclosure

This project was designed and written with an AI coding assistant (Anthropic's Claude), operated by the submitting participant during the hackathon window. Every line was reviewed and is covered by the test suite. The product itself calls open-weight models (Llama 3.2, Llama 3.1, Mistral Small 3.1) through Cloudflare Workers AI.

## License

MIT
