import { expect, test } from '@playwright/test';

test('live inventory exactly matches the read-only API snapshot', async ({ page, request }) => {
  const response = await request.get('/api/v1/ues');
  expect(response.ok()).toBe(true);
  const inventory = await response.json();
  expect(inventory.configured_count).toBe(inventory.items.length);
  expect(inventory.cache_version).toEqual(expect.any(Number));
  expect(inventory.cache_fresh).toEqual(expect.any(Boolean));

  await page.goto('/#/ues');
  const statePanel = page.locator('.panel').filter({ hasText: 'Configured UE state' });
  await expect(statePanel.locator('tbody tr')).toHaveCount(inventory.configured_count);
  for (const item of inventory.items) {
    const row = statePanel.locator('tbody tr').filter({ hasText: item.id });
    await expect(row).toHaveCount(1);
    await expect(row.getByText(item.process_state, { exact: true })).toBeVisible();
    await expect(row.getByText(item.registration_state, { exact: true })).toBeVisible();
    await expect(row.getByText(item.pdu_session, { exact: true })).toBeVisible();
  }
});
