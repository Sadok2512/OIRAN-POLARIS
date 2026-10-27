/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE?: string;
  readonly VITE_APP_SIMULATOR_URL?: string;
  readonly VITE_APP_PROBE_MANAGER_URL?: string;
  readonly VITE_APP_OIRAN_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
