// Cloudflare Worker entry (single-script deployment): static assets + API.
import { handleApi } from './api.js';
import { ASSETS } from './assets.js';

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'x-frame-options': 'DENY',
  'access-control-allow-origin': '*', // static assets are public; lets docs/mirrors fetch them
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) return handleApi(request, env);
    const path = url.pathname === '/' ? '/index.html' : url.pathname;
    const asset = ASSETS[path];
    if (!asset) return new Response('Not found', { status: 404, headers: { 'content-type': 'text/plain', ...SECURITY_HEADERS } });
    return new Response(asset.body, { headers: { 'content-type': asset.type, 'cache-control': 'public, max-age=300', ...SECURITY_HEADERS } });
  },
};
