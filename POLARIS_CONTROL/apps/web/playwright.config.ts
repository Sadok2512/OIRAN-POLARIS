import{defineConfig}from'@playwright/test';
const runtimeEnv=(globalThis as {process?:{env?:Record<string,string|undefined>}}).process?.env;
export default defineConfig({testDir:'./e2e',timeout:30000,workers:1,use:{baseURL:runtimeEnv?.POLARIS_E2E_BASE_URL??'http://127.0.0.1:49153',viewport:{width:1440,height:900},trace:'retain-on-failure'},reporter:[['list'],['json',{outputFile:'../../tests/V3_1_E2E_RESULTS.json'}]]});
