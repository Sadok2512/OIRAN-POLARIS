// 2.10.0 (devmat) — Session Explorer filters end-to-end spec.
//
// Couvre les deux chemins critiques :
//   * Filtres avancés visibles en Viewer (messages + causes +
//     failures_only) — chips togglables, le panneau garde l'état
//     local sans faire entrer l'IMSI/TMSI éventuel dans l'URL.
//   * Identity lookup caché pour Viewer, visible pour Operator.
//
// Produit aussi les captures 1280/1440/1920 en light + dark.

import { expect, test, type Page } from '../../apps/web/node_modules/@playwright/test';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const ROOT = path.resolve(process.cwd(), '../..');
const screenshots = path.join(ROOT, 'OIRAN_V2_10_SESSION_FILTERS_SCREENSHOTS');
const historical = 'OIRAN_5G_PDU_SESSION_DATA_V1';

async function openExplorer(page: Page, query = '') {
  await page.goto(`/investigation/sessions${query}`);
  await expect(page.getByRole('heading', { name: 'Session Explorer' })).toBeVisible();
}

test.describe('V2.10 Session Explorer advanced filters', () => {
  test('viewer sees messages + causes + failures_only but NOT identity', async ({ page }) => {
    await openExplorer(page, `?dataset_id=${historical}`);
    await page.getByRole('button', { name: /Advanced/ }).click();
    await expect(page.getByRole('heading', { name: 'Messages' })).toBeVisible();
    await expect(page.getByRole('heading', { name: /Causes/ })).toBeVisible();
    await expect(page.getByLabel('Failures only')).toBeVisible();
    // Identity section: visible label but contains the role-gate
    // message (`operator-only`) instead of the input for Viewers.
    await expect(page.getByRole('heading', { name: /Identity lookup/ })).toBeVisible();
    await expect(page.getByText(/Sign in as an operator/)).toBeVisible();
    await expect(page.getByLabel('Identity value')).toHaveCount(0);
  });

  test('toggling a message chip keeps identity out of the URL', async ({ page }) => {
    await openExplorer(page, `?dataset_id=${historical}`);
    await page.getByRole('button', { name: /Advanced/ }).click();
    // Click any PDUSession-related chip (dataset-dependent).
    const chip = page.locator('.chip.toggle').first();
    await chip.click();
    const urlAfter = new URL(page.url());
    // URL must not contain any identity-ish param (POST-only invariant).
    expect(urlAfter.searchParams.has('identity')).toBe(false);
    expect(urlAfter.searchParams.has('imsi')).toBe(false);
    expect(urlAfter.searchParams.has('supi')).toBe(false);
  });

  test('available_causes endpoint responds and lists shape-correct causes', async ({ request }) => {
    const response = await request.get('/api/v1/sessions/available_causes');
    expect(response.status()).toBe(200);
    const body = await response.json();
    const causes = body.data?.causes;
    expect(Array.isArray(causes)).toBe(true);
    for (const cause of causes) {
      expect(typeof cause.domain).toBe('string');
      expect(typeof cause.value).toBe('string');
      expect(typeof cause.is_failure).toBe('boolean');
      expect(cause.session_count).toBeGreaterThanOrEqual(1);
    }
  });

  test('POST /sessions/filter without identity works for viewer', async ({ request }) => {
    const response = await request.post('/api/v1/sessions/filter', {
      data: { failures_only: false, page_size: 10 },
      headers: { 'content-type': 'application/json' },
    });
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(Array.isArray(body.data)).toBe(true);
    expect(body.meta.role).toBe('viewer');
    expect(body.meta.identity_matched_pseudonym).toBeUndefined();
  });

  test('POST /sessions/filter rejects viewer-supplied identity hint', async ({ request }) => {
    const response = await request.post('/api/v1/sessions/filter', {
      data: { identity: { kind: 'supi_or_imsi', value: 'imsi-208010001234567' } },
      headers: { 'content-type': 'application/json' },
    });
    expect(response.status()).toBe(403);
    const body = await response.json();
    expect(body.error.code).toBe('IDENTITY_FILTER_OPERATOR_REQUIRED');
    // Raw identity must NEVER appear in the error payload.
    expect(JSON.stringify(body)).not.toContain('208010001234567');
  });

  for (const viewport of [
    { width: 1280, height: 800 },
    { width: 1440, height: 900 },
    { width: 1920, height: 1080 },
  ]) {
    for (const theme of ['light', 'dark'] as const) {
      test(`screenshot ${theme} ${viewport.width}x${viewport.height}`, async ({ page }) => {
        await fs.mkdir(screenshots, { recursive: true });
        await page.setViewportSize(viewport);
        await page.goto('/');
        await page.evaluate((value) => localStorage.setItem('oiran.theme', value), theme);
        await openExplorer(page, `?dataset_id=${historical}`);
        await page.getByRole('button', { name: /Advanced/ }).click();
        await expect(page.getByRole('heading', { name: 'Messages' })).toBeVisible();
        const file = path.join(
          screenshots,
          `v2_10_session_filters_${theme}_${viewport.width}x${viewport.height}.png`,
        );
        await page.screenshot({ path: file, fullPage: true });
      });
    }
  }
});
