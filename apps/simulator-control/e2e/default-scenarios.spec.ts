import { expect, test, type Page } from '@playwright/test';
import { DEFAULT_SCENARIO_TEMPLATES } from '../src/scenarios/defaultTemplates';

const json = (body: unknown, status = 200) => ({
  status,
  contentType: 'application/json',
  body: JSON.stringify(body),
});

async function mockPolaris(page: Page) {
  await page.route('**/polaris-api/v1/**', (route) => route.fulfill(json({ items: [] })));
  await page.route('**/polaris-api/v1/auth/me', (route) => route.fulfill(json({
    authenticated: true,
    username: 'operator-test',
    role: 'operator',
    can_start: true,
    can_manage_permissions: false,
  })));
  await page.route('**/polaris-api/v1/capabilities', (route) => route.fulfill(json({
    live_control: false,
    approval_state: 'OPERATOR_AUTHORIZATION_REQUIRED',
    max_ues: 10,
    max_nodes: 2,
    registration_modes: ['STAGGERED'],
    traffic_protocols: ['UDP'],
    approved_destinations: [],
    profiles: [],
    technologies: [],
    services: [],
    scenario_step_kinds: ['ue_start', 'ue_stop', 'pdu_establish', 'pdu_release', 'udp_traffic', 'wait'],
  })));
  await page.route('**/polaris-api/v1/lte/status', (route) => route.fulfill(json({
    technology: 'LTE 4G',
    simulator: 'srsRAN',
    certified: false,
    live_enabled: false,
    grant_active: false,
    safety_ready: true,
    traffic_allowed: false,
  })));
  await page.route('**/polaris-api/v1/scenario-templates', (route) => route.fulfill(json({
    schema_version: 'polaris.scenario-template-catalog.v1',
    total: DEFAULT_SCENARIO_TEMPLATES.length,
    multi_ue_templates: false,
    defaults: { ue_count: 1, execution: 'ONCE', transport: 'UDP', rate_bps: 1_000_000, duration_seconds: 60, tcp_authorized: false, multi_ue: false },
    items: DEFAULT_SCENARIO_TEMPLATES.map((item) => ({
      template_id: item.id,
      version: '1.0.0',
      rat: item.rat,
      simulator: item.simulator,
      description: item.description,
      steps: item.definition.steps,
      parameters: { ue_count: 1, execution: 'ONCE', transport: 'UDP', rate_bps: (item.throughputKbps ?? 0) * 1_000, duration_seconds: item.durationSeconds, tcp_authorized: false, multi_ue: false },
      required_capabilities: item.prerequisites,
      backend_support: item.support,
      certification_required: item.support === 'CERTIFICATION_REQUIRED',
      read_only: true,
    })),
  })));
  await page.route('**/polaris-api/v1/scenario-definitions', async (route) => {
    if (route.request().method() === 'POST') {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill(json({ ...body, version: 1, created_at_epoch_s: 1, updated_at_epoch_s: 1 }));
      return;
    }
    await route.fulfill(json({ items: [], total: 0, schema_version: 1 }));
  });
  await page.route('**/polaris-api/v1/scenario-definitions/**', async (route) => {
    const method = route.request().method();
    const body = route.request().postDataJSON() as Record<string, unknown>;
    if (method === 'POST' && route.request().url().endsWith('/clone')) {
      await route.fulfill(json({
        id: body.target_id,
        name: 'LTE Full Session copy',
        loop_count: 1,
        steps: [],
        version: 1,
      }, 201));
      return;
    }
    if (method === 'PUT') {
      await route.fulfill(json({ ...body, version: 2, created_at_epoch_s: 1, updated_at_epoch_s: 2 }));
      return;
    }
    await route.fulfill(json({ error: 'not stubbed' }, 404));
  });
}

test.beforeEach(async ({ page }) => {
  await mockPolaris(page);
  await page.addInitScript(() => {
    localStorage.setItem('polaris.featureFlags.v2', JSON.stringify({
      scenarioBackend: true,
      profileBackend: true,
      scenarioTemplates: true,
      polarisProvisioning: true,
    }));
  });
});

test('templates filter, load, customize and save an immutable LTE copy', async ({ page }, testInfo) => {
  await page.goto('./scenarios');
  await page.getByTestId('scenarios-tab-templates').click();
  await expect(page.getByTestId('templates-catalog')).toBeVisible();
  await expect(page.locator('[data-testid^="template-card-"]')).toHaveCount(13);

  await page.getByLabel('Template RAT filter').selectOption('LTE');
  await expect(page.locator('[data-testid^="template-card-"]')).toHaveCount(6);
  await expect(page.getByText('CERTIFICATION_REQUIRED').first()).toBeVisible();
  await page.screenshot({
    path: `docs/screenshots/default-scenarios/${testInfo.project.name}-lte.png`,
    fullPage: true,
  });

  await page.getByLabel('Template RAT filter').selectOption('5G_SA');
  await expect(page.locator('[data-testid^="template-card-"]')).toHaveCount(7);
  await expect(page.getByText('5G SA Full Session')).toBeVisible();
  await page.screenshot({
    path: `docs/screenshots/default-scenarios/${testInfo.project.name}-5g.png`,
    fullPage: true,
  });

  await page.getByLabel('Template RAT filter').selectOption('LTE');
  await page.getByTestId('template-customize-tpl-lte-full-session').click();
  await expect(page.getByTestId('builder-template-source')).toContainText('immutable source');
  await expect(page.locator('[data-testid^="step-row-"]')).toHaveCount(5);
  await expect(page.getByTestId('builder-run')).toBeDisabled();
  await expect(page.getByTestId('builder-run')).toHaveAttribute('title', /certification|backend execution support/i);

  await page.getByTestId('scenario-name').fill('Playwright LTE copy');
  const cloned = page.waitForRequest((request) =>
    request.url().endsWith('/scenario-definitions/tpl-lte-full-session/clone') && request.method() === 'POST');
  const saved = page.waitForRequest((request) =>
    request.url().includes('/scenario-definitions/') && request.method() === 'PUT');
  await page.getByTestId('builder-save').click();
  const cloneRequest = await cloned;
  expect((cloneRequest.postDataJSON() as { target_id: string }).target_id).not.toMatch(/^tpl-/);
  const request = await saved;
  const body = request.postDataJSON() as { id: string; name: string; steps: Array<{ type: string }> };
  expect(body.id).not.toBe('tpl-lte-full-session');
  expect(body.name).toBe('Playwright LTE copy');
  expect(body.steps.map((entry) => entry.type)).toEqual([
    'lte_attach', 'lte_traffic_ul', 'lte_traffic_dl', 'wait', 'lte_detach',
  ]);

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflow).toBe(false);
});
