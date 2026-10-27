#!/usr/bin/env node
// Hardened static server used only for the authenticated preview behind
// the Cloudflare tunnel. Loopback bind, GET/HEAD only, path-traversal
// prevention, SPA fallback, security headers. Never exposed on 0.0.0.0.
//
// Usage: PORT=8020 node scripts/serve-static.mjs <dist-root>
import http from 'node:http';
import { createReadStream, promises as fs } from 'node:fs';
import { extname, join, normalize, resolve, sep } from 'node:path';

const PORT = Number(process.env.PORT ?? 8080);
const HOST = process.env.HOST ?? '127.0.0.1'; // loopback only
const DIST = resolve(process.argv[2] ?? 'dist');

const CONNECT_SRC = process.env.CSP_CONNECT_SRC ?? "'self' https://api.qoebit.net";
const STYLE_SRC_EXTRA = "https://rsms.me";
const FONT_SRC = "https://rsms.me";

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.map': 'application/json; charset=utf-8',
};

function sendHeaders(res, status, type, extra = {}) {
  res.writeHead(status, {
    'Content-Type': type,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Content-Security-Policy': [
      "default-src 'self'",
      "img-src 'self' data:",
      `style-src 'self' 'unsafe-inline' ${STYLE_SRC_EXTRA}`,
      `font-src ${FONT_SRC}`,
      `connect-src ${CONNECT_SRC}`,
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'none'",
    ].join('; '),
    'Cache-Control': status === 200 ? 'public, max-age=300' : 'no-store',
    ...extra,
  });
}

async function resolveFile(urlPath) {
  // Strip query/hash and leading /
  const [rawPath] = urlPath.split('?');
  const safePath = normalize(decodeURIComponent(rawPath)).replace(/^\/+/, '');
  const target = resolve(DIST, safePath);
  if (!target.startsWith(DIST + sep) && target !== DIST) {
    return null; // path traversal
  }
  try {
    const stat = await fs.stat(target);
    if (stat.isDirectory()) {
      const index = join(target, 'index.html');
      await fs.stat(index);
      return index;
    }
    return target;
  } catch {
    return null;
  }
}

async function serve(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    sendHeaders(res, 405, 'text/plain; charset=utf-8', { Allow: 'GET, HEAD' });
    res.end('Method Not Allowed');
    return;
  }
  const url = req.url ?? '/';
  let file = await resolveFile(url);
  if (!file) {
    // SPA fallback — rewrite to index.html for client-side routers.
    file = await resolveFile('/index.html');
  }
  if (!file) {
    sendHeaders(res, 404, 'text/plain; charset=utf-8');
    res.end('Not found');
    return;
  }
  const type = MIME[extname(file)] ?? 'application/octet-stream';
  sendHeaders(res, 200, type);
  if (req.method === 'HEAD') {
    res.end();
    return;
  }
  createReadStream(file).pipe(res);
}

http
  .createServer((req, res) => {
    serve(req, res).catch((err) => {
      console.error('serve error', err);
      sendHeaders(res, 500, 'text/plain; charset=utf-8');
      res.end('Internal Server Error');
    });
  })
  .listen(PORT, HOST, () => {
    console.log(`static server on http://${HOST}:${PORT} serving ${DIST}`);
  });
