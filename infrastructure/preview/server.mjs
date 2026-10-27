#!/usr/bin/env node
import http from 'node:http';
import { createReadStream, promises as fs } from 'node:fs';
import { extname, resolve, sep } from 'node:path';

const host = '0.0.0.0';
const port = Number(process.env.PREVIEW_PORT ?? 8020);
const root = resolve(process.env.PREVIEW_PUBLIC_ROOT ?? new URL('./public/', import.meta.url).pathname);
const allowedClient = process.env.ALLOWED_CLIENT_IP ?? '*';

const applications = new Set(['portal', 'probe-manager', 'simulator', 'analyzer']);
const mime = {
  '.css': 'text/css; charset=utf-8', '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon', '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.png': 'image/png',
  '.svg': 'image/svg+xml', '.woff': 'font/woff', '.woff2': 'font/woff2',
};

function securityHeaders(type) {
  return {
    'Cache-Control': type.startsWith('text/html') ? 'no-store' : 'public, max-age=300',
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://rsms.me; font-src 'self' https://rsms.me; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    'Content-Type': type,
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  };
}

function clientIp(request) {
  const address = request.socket.remoteAddress ?? '';
  return address.startsWith('::ffff:') ? address.slice(7) : address;
}

function localPrivateAccess(request) {
  return ['127.0.0.1', '::1'].includes(clientIp(request));
}

function reject(response, status, code, message, allow) {
  response.writeHead(status, {
    ...securityHeaders('application/json; charset=utf-8'),
    ...(allow ? { Allow: allow } : {}),
  });
  response.end(JSON.stringify({ error: { code, message } }));
}

function proxyApi(request, response, targetPort, targetPath) {
  const readOnly = request.method === 'GET' || request.method === 'HEAD';
  if (!readOnly && !localPrivateAccess(request)) {
    reject(
      response,
      403,
      'PUBLIC_PREVIEW_READ_ONLY',
      'Mutating operations require the private localhost tunnel and backend authentication.',
      'GET, HEAD',
    );
    return;
  }

  const forwardedHeaders = {
    Accept: request.headers.accept ?? 'application/json',
    ...(request.headers['content-type'] ? { 'Content-Type': request.headers['content-type'] } : {}),
    ...(request.headers.authorization ? { Authorization: request.headers.authorization } : {}),
    ...(request.headers.cookie ? { Cookie: request.headers.cookie } : {}),
    ...(request.headers['x-csrf-token'] ? { 'X-CSRF-Token': request.headers['x-csrf-token'] } : {}),
  };
  const upstream = http.request({
    host: '127.0.0.1', port: targetPort, method: request.method,
    path: targetPath, headers: forwardedHeaders, timeout: 10_000,
  }, (upstreamResponse) => {
    const type = upstreamResponse.headers['content-type'] ?? 'application/octet-stream';
    const responseHeaders = {
      ...securityHeaders(type),
      'Cache-Control': 'no-store',
      ...(upstreamResponse.headers['content-disposition'] ? { 'Content-Disposition': upstreamResponse.headers['content-disposition'] } : {}),
      ...(upstreamResponse.headers['www-authenticate'] ? { 'WWW-Authenticate': upstreamResponse.headers['www-authenticate'] } : {}),
      ...(upstreamResponse.headers['set-cookie'] ? { 'Set-Cookie': upstreamResponse.headers['set-cookie'] } : {}),
    };
    response.writeHead(upstreamResponse.statusCode ?? 502, responseHeaders);
    upstreamResponse.pipe(response);
  });
  upstream.on('timeout', () => upstream.destroy(new Error('upstream timeout')));
  upstream.on('error', () => {
    if (response.headersSent) return response.destroy();
    reject(response, 502, 'BACKEND_UNREACHABLE', 'The selected backend is unreachable.');
  });
  request.pipe(upstream);
}

async function staticFile(pathname) {
  const match = pathname.match(/^\/(portal|probe-manager|simulator|analyzer)(?:\/(.*))?$/);
  if (!match || !applications.has(match[1])) return null;
  const appRoot = resolve(root, match[1]);
  const candidate = resolve(appRoot, match[2] || 'index.html');
  if (candidate !== appRoot && !candidate.startsWith(`${appRoot}${sep}`)) return null;
  try {
    if ((await fs.stat(candidate)).isFile()) return candidate;
  } catch {}
  return resolve(appRoot, 'index.html');
}

const server = http.createServer(async (request, response) => {
  if (allowedClient !== '*' && clientIp(request) !== allowedClient) {
    reject(response, 403, 'CLIENT_NOT_ALLOWED', 'Client address is not allowlisted.');
    return;
  }
  const url = new URL(request.url ?? '/', 'http://preview.invalid');
  if (url.pathname === '/api/v1' || url.pathname.startsWith('/api/v1/')) {
    proxyApi(request, response, 49152, `${url.pathname}${url.search}`);
    return;
  }
  if (url.pathname === '/analyzer-api/v1' || url.pathname.startsWith('/analyzer-api/v1/')) {
    proxyApi(request, response, 49152, `${url.pathname.replace('/analyzer-api', '/api')}${url.search}`);
    return;
  }
  if (url.pathname === '/polaris-api/v1' || url.pathname.startsWith('/polaris-api/v1/')) {
    proxyApi(request, response, 49153, `${url.pathname.replace('/polaris-api', '/api')}${url.search}`);
    return;
  }
  if (!['GET', 'HEAD'].includes(request.method ?? 'GET')) {
    reject(response, 405, 'METHOD_NOT_ALLOWED', 'Static application routes accept GET and HEAD only.', 'GET, HEAD');
    return;
  }
  if (url.pathname === '/') {
    response.writeHead(302, { Location: '/portal/' });
    response.end();
    return;
  }
  if ([...applications].some((app) => url.pathname === `/${app}`)) {
    response.writeHead(308, { Location: `${url.pathname}/` });
    response.end();
    return;
  }
  const file = await staticFile(url.pathname);
  if (!file) {
    reject(response, 404, 'NOT_FOUND', 'Preview resource not found.');
    return;
  }
  const type = mime[extname(file)] ?? 'application/octet-stream';
  response.writeHead(200, securityHeaders(type));
  if (request.method === 'HEAD') response.end();
  else createReadStream(file).pipe(response);
});

server.listen(port, host, () => {
  console.log(`OIRAN-POLARIS preview listening on ${host}:${port}`);
});
