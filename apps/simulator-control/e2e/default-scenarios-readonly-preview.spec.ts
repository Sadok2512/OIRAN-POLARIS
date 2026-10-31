import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('polaris.featureFlags.v2', JSON.stringify({
      scenarioBackend: true,
      profileBackend: true,
      scenarioTemplates: true,
      polarisProvisioning: true,
    }));
  });
});

test('read-only preview exposes all templates and locks mutations', async ({ page }, testInfo) => {
  await page.goto('./scenarios');
  await page.getByTestId('scenarios-tab-templates').click();
  await expect(page.getByTestId('templates-catalog')).toBeVisible();
  await expect(page.locator('[data-testid^="template-card-"]')).toHaveCount(13);

  const statuses = await page.locator('[data-testid^="template-card-"]').evaluateAll((cards) =>
    cards.map((card) => card.textContent ?? ''));
  expect(statuses.filter((text) => text.includes('SUPPORTED'))).toHaveLength(3);
  expect(statuses.filter((text) => text.includes('CERTIFICATION_REQUIRED'))).toHaveLength(2);
  expect(statuses.filter((text) => text.includes('BACKEND_REQUIRED'))).toHaveLength(8);

  const mutation = await page.request.post('/polaris-api/v1/scenario-definitions', {
    data: { id: 'must-not-be-created' },
  });
  expect(mutation.status()).toBe(423);
  expect(await mutation.json()).toEqual({ error: 'READ_ONLY_PREVIEW' });

  await page.screenshot({
    path: `docs/screenshots/default-scenarios/${testInfo.project.name}-readonly-preview.png`,
    fullPage: true,
  });
});
