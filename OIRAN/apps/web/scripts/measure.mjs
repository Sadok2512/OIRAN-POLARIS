import { chromium } from '@playwright/test';

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const started = performance.now();
await page.goto('http://127.0.0.1:49152/');
await page.getByText('Probe & Capture Manager', { exact: true }).waitFor();
const publicLoadMs = performance.now() - started;
const sessionStarted = performance.now();
await page.goto('http://127.0.0.1:49152/investigation/sessions/5g-UE-A-pdu-1');
await page.getByText('5g-UE-A-pdu-1').first().waitFor();
const sessionRenderMs = performance.now() - sessionStarted;
const flowStarted = performance.now();
await page.goto('http://127.0.0.1:49152/investigation/callflow/5g-UE-A-pdu-1');
await page.locator('.flow-event').first().waitFor();
const callflowRenderMs = performance.now() - flowStarted;
const browserHeapBytes = await page.evaluate(() => performance.memory?.usedJSHeapSize ?? null);
console.log(JSON.stringify({ publicLoadMs, sessionRenderMs, callflowRenderMs, browserHeapBytes }, null, 2));
await browser.close();
