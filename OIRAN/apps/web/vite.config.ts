import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const runtimeEnv=(globalThis as {process?:{env?:Record<string,string|undefined>}}).process?.env;
const apiTarget=runtimeEnv?.OIRAN_DEV_API_TARGET??'http://127.0.0.1:49152';

export default defineConfig({
  plugins: [react()],
  server: { host: '127.0.0.1', port: 4173, proxy: { '/api': apiTarget } },
  build: { target: 'es2022', sourcemap: false, chunkSizeWarningLimit: 700 },
});
