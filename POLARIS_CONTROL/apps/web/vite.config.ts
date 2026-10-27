import {defineConfig} from 'vite';import react from '@vitejs/plugin-react';
export default defineConfig({plugins:[react()],server:{host:'127.0.0.1',port:5174,proxy:{'/api':'http://127.0.0.1:49153'}},build:{sourcemap:false},test:{environment:'jsdom',setupFiles:'./src/test-setup.ts',include:['src/**/*.test.tsx']}});
