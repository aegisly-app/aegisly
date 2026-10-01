// Local dev server: static files from public/ + API on an in-memory D1 shim. node --no-warnings test/devserver.mjs
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { createD1 } from './d1shim.mjs';
import { handleApi } from '../src/api.js';

const env = { DB: createD1(new URL('../schema.sql', import.meta.url)) };
const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript' };
const root = new URL('../public/', import.meta.url).pathname;
http.createServer(async (req, res) => {
  const url = `http://${req.headers.host}${req.url}`;
  if (req.url.startsWith('/api/')) {
    const chunks = []; for await (const c of req) chunks.push(c);
    const r = await handleApi(new Request(url, { method: req.method, headers: req.headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks) }), env);
    res.writeHead(r.status, Object.fromEntries(r.headers)); res.end(Buffer.from(await r.arrayBuffer())); return;
  }
  let p = new URL(url).pathname; if (p === '/') p = '/index.html';
  try { const f = await readFile(join(root, normalize(p))); res.writeHead(200, { 'content-type': types[extname(p)] || 'application/octet-stream' }); res.end(f); }
  catch { res.writeHead(404); res.end('not found'); }
}).listen(process.env.PORT || 8788, () => console.log('dev server on', process.env.PORT || 8788));
