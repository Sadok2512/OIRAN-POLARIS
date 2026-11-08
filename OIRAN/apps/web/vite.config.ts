import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import pkg from './package.json';

const runtimeEnv=(globalThis as {process?:{env?:Record<string,string|undefined>}}).process?.env;
const apiTarget=runtimeEnv?.OIRAN_DEV_API_TARGET??'http://127.0.0.1:49152';
// 2.8.1: the Analyzer is served under `/analyzer/` in production (ANR1
// deploy was rolled back when the dist referenced `/assets/...` while
// nginx served the SPA at `/analyzer/assets/...`, yielding 404s on
// every chunk). The prefix is overridable at build time via
// `OIRAN_WEB_BASE` so operators can serve the Analyzer elsewhere
// without a patch; the default matches the production reverse proxy.
const basePath=runtimeEnv?.OIRAN_WEB_BASE??'/analyzer/';

// 2.9.3 (#9): the web bundle version is read from `apps/web/package.json`
// at build time — SINGLE source of truth. The 2.9.2 follow-up #2 bumped
// package.json 2.9.0 → 2.9.1 but left the previous hardcoded literal
// `'2.9.0'` here, so the Analyzer footer still showed `web 2.9.0` on an
// otherwise 2.9.1 bundle. `tsconfig.node.json` enables
// `resolveJsonModule` + `esModuleInterop` so this import is typed
// without `@types/node`; `src/test/version-footer.test.tsx` enforces
// `import.meta.env.VITE_WEB_VERSION === pkg.version` on every vitest run.
const WEB_VERSION = pkg.version;

export default defineConfig({
  base: basePath,
  define: { 'import.meta.env.VITE_WEB_VERSION': JSON.stringify(WEB_VERSION) },
  plugins: [react()],
  server: { host: '127.0.0.1', port: 4173, proxy: { '/api': apiTarget } },
  preview: { host: '127.0.0.1', port: 4173, proxy: { '/api': apiTarget } },
  build: { target: 'es2022', sourcemap: false, chunkSizeWarningLimit: 700 },
});
