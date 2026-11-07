import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const runtimeEnv=(globalThis as {process?:{env?:Record<string,string|undefined>}}).process?.env;
const apiTarget=runtimeEnv?.OIRAN_DEV_API_TARGET??'http://127.0.0.1:49152';
// 2.8.1: the Analyzer is served under `/analyzer/` in production (ANR1
// deploy was rolled back when the dist referenced `/assets/...` while
// nginx served the SPA at `/analyzer/assets/...`, yielding 404s on
// every chunk). The prefix is overridable at build time via
// `OIRAN_WEB_BASE` so operators can serve the Analyzer elsewhere
// without a patch; the default matches the production reverse proxy.
const basePath=runtimeEnv?.OIRAN_WEB_BASE??'/analyzer/';

// 2.9.0 (#9): surface the web bundle's own version at runtime so the
// Analyzer footer can show `web <X.Y.Z>` alongside the backend API
// version. The value is pinned here and asserted against
// `apps/web/package.json` by `src/test/version-footer.test.tsx` — a
// desync fails the vitest build so a bump can never ship without
// touching this file.
const WEB_VERSION = '2.9.0';

export default defineConfig({
  base: basePath,
  define: { 'import.meta.env.VITE_WEB_VERSION': JSON.stringify(WEB_VERSION) },
  plugins: [react()],
  server: { host: '127.0.0.1', port: 4173, proxy: { '/api': apiTarget } },
  preview: { host: '127.0.0.1', port: 4173, proxy: { '/api': apiTarget } },
  build: { target: 'es2022', sourcemap: false, chunkSizeWarningLimit: 700 },
});
