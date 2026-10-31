import { createReadStream, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const host = '127.0.0.1';
const port = Number(process.env.POLARIS_READONLY_PREVIEW_PORT ?? 4331);
const root = normalize(join(fileURLToPath(new URL('.', import.meta.url)), '..', 'dist'));
const mime = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};

createServer((request, response) => {
  const url = new URL(request.url ?? '/', `http://${host}:${port}`);
  if (url.pathname.startsWith('/polaris-api/')) {
    response.setHeader('content-type', 'application/json; charset=utf-8');
    response.setHeader('cache-control', 'no-store');
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method ?? 'GET')) {
      response.writeHead(423).end(JSON.stringify({ error: 'READ_ONLY_PREVIEW' }));
      return;
    }
    response.writeHead(404).end(JSON.stringify({ error: 'READ_ONLY_PREVIEW_NO_BACKEND' }));
    return;
  }

  const relative = url.pathname.startsWith('/simulator/')
    ? url.pathname.slice('/simulator/'.length)
    : '';
  let file = normalize(join(root, relative || 'index.html'));
  if (!file.startsWith(root)) {
    response.writeHead(403).end();
    return;
  }
  try {
    if (!statSync(file).isFile()) file = join(root, 'index.html');
  } catch {
    file = join(root, 'index.html');
  }
  response.setHeader('content-type', mime[extname(file)] ?? 'application/octet-stream');
  if (file.endsWith('index.html')) response.setHeader('cache-control', 'no-store');
  response.writeHead(200);
  createReadStream(file).pipe(response);
}).listen(port, host, () => {
  process.stdout.write(`read-only preview http://${host}:${port}/simulator/\n`);
});
