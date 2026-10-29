// 0.9.2 — Playwright capture of the Provisioning page with the new
// polarisProvisioning-ON default.
//
// Scope:
//   * Default state: flag is ON (0.9.2 default), /subscribers returns a
//     mocked list → the Provisioning table renders.
//   * Error state: /subscribers returns 503 with a bounded JSON body →
//     the page surfaces the exact HTTP status + backend code + message
//     instead of a "backend pending" placeholder.
//
// Mocked API — no live POLARIS. All identity material renders PROTECTED.

import { test, expect, type Page } from '@playwright/test';

async function mockBase(page: Page) {
  await page.route('**/polaris-api/v1/auth/me', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        authenticated: true,
        username: 'ops',
        role: 'Operator',
        can_start: true,
        can_manage_permissions: false,
      }),
    }),
  );
  await page.route('**/polaris-api/v1/capabilities', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        live_control: false,
        approval_state: 'NOT_REQUESTED',
        max_ues: 10,
        max_nodes: 2,
        registration_modes: [],
        traffic_protocols: [],
        approved_destinations: [],
        profiles: [],
        technologies: [],
        services: [],
      }),
    }),
  );
}

test.describe('provisioning page (polarisProvisioning ON by default)', () => {
  test('renders the subscriber list without any identity in clear', async ({ page }) => {
    await mockBase(page);
    await page.route('**/polaris-api/v1/subscribers', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          items: [
            {
              subscriber_id: 'sub-protected-01',
              owner: 'ops-nancy',
              imsi: 'PROTECTED',
              provisioning_status: 'ACTIVE',
              updated_at_epoch_s: 1_730_200_000,
            },
            {
              subscriber_id: 'sub-protected-02',
              owner: 'ops-nancy',
              imsi: 'PROTECTED',
              provisioning_status: 'PROVISIONING',
              updated_at_epoch_s: 1_730_200_010,
            },
          ],
          total: 2,
        }),
      }),
    );

    await page.goto('provisioning');
    const table = page.getByTestId('provisioning-subscribers');
    await expect(table).toBeVisible();
    await expect(table).toContainText('sub-protected-01');
    await expect(table).toContainText('PROTECTED');

    await page.screenshot({
      path: 'docs/screenshots/provisioning-flag-on.png',
      fullPage: true,
    });
  });

  test('surfaces the real API error (HTTP status + code + message) when the backend is unavailable', async ({ page }) => {
    await mockBase(page);
    // OIRAN-style error object ({error:{code,message}}) so the UI surfaces
    // the message distinctly from the code; POLARIS-style string errors
    // deduplicate automatically in `errorReason`.
    await page.route('**/polaris-api/v1/subscribers', (route) =>
      route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({
          error: {
            code: 'OPEN5GS_DATABASE_UNAVAILABLE',
            message: 'mongosh exec exited with 137 (OOM)',
          },
        }),
      }),
    );

    await page.goto('provisioning');
    const banner = page.getByTestId('provisioning-list-error');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText('HTTP 503');
    await expect(banner).toContainText('OPEN5GS_DATABASE_UNAVAILABLE');
    await expect(banner).toContainText('mongosh');

    await page.screenshot({
      path: 'docs/screenshots/provisioning-backend-error.png',
      fullPage: true,
    });
  });
});
