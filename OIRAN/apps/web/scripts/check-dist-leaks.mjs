#!/usr/bin/env node
// Fails the build (exit 1) if any fixture-looking marker is found inside
// dist/. The markers are strings that only appear in test fixtures or
// screenshot scripts; they must never reach the production bundle.
//
// Usage: node scripts/check-dist-leaks.mjs
// Wired into `npm run build` via package.json.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DIST_DIR = resolve(__dirname, '..', 'dist');

// Markers that must NEVER appear in a production bundle. "POLARIS_5G_SA"
// is intentionally NOT on this list — it is the real backend capture
// profile constant the API expects on `/captures/validate` and
// `/captures/start`, so it legitimately ships. Dataset ids and probe ids
// are forbidden because the only place they belong is a test fixture.
const FORBIDDEN_MARKERS = [
  'oiran-vprobe-local-01',
  'OIRAN_5G_PDU_SESSION_DATA_V1',
];

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const info = statSync(full);
    if (info.isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

const files = walk(DIST_DIR).filter(
  (file) => file.endsWith('.js') || file.endsWith('.css') || file.endsWith('.html'),
);

const hits = [];
for (const file of files) {
  const text = readFileSync(file, 'utf8');
  for (const marker of FORBIDDEN_MARKERS) {
    if (text.includes(marker)) {
      hits.push({ file, marker });
    }
  }
}

if (hits.length === 0) {
  console.log(`check-dist-leaks: clean (${files.length} files scanned, ${FORBIDDEN_MARKERS.length} markers)`);
  process.exit(0);
}

console.error('check-dist-leaks: FIXTURE LEAK IN dist/');
for (const hit of hits) {
  console.error(`  ${hit.marker.padEnd(32)} → ${hit.file}`);
}
process.exit(1);
