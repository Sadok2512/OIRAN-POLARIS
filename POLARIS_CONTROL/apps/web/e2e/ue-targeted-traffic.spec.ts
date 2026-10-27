import { expect, test } from '@playwright/test';

test('operator targets only an eligible controller-owned UE', async ({ page }) => {
  const shared = {
    id: 'UE-PSEUDONYM-01', internal_ue_id: 'UE-01', controller_owned: false,
    traffic_target_verified: false, process_state: 'RUNNING', registration_state: 'REGISTERED',
    pdu_session: 'ACTIVE', ue_ip: '10.46.0.4', traffic_state: 'IDLE', last_event: null,
    actions: { start: false, stop: false, pdu_start: false, pdu_stop: false, traffic: false, reason: 'SHARED_UE_PROTECTED' },
  };
  const owned = {
    id: 'UE-PSEUDONYM-04', internal_ue_id: 'UE-04', controller_owned: true,
    traffic_target_verified: true, process_state: 'RUNNING', registration_state: 'REGISTERED',
    pdu_session: 'ACTIVE', ue_ip: '10.46.0.6', traffic_state: 'IDLE', last_event: null,
    actions: { start: false, stop: true, pdu_start: false, pdu_stop: false, traffic: true, reason: 'READY_FOR_BOUNDED_TRAFFIC' },
  };
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { authenticated: true, username: 'operator-test', role: 'operator', can_start: true, can_manage_permissions: false, csrf_token: 'mock' } }));
  await page.route('**/api/v1/system/health', route => route.fulfill({ json: { disk: { usage_percent: 50 }, memory: { available_bytes: 4294967296 }, cpu: { usage_percent: 10 }, decision: { state: 'NORMAL' } } }));
  await page.route('**/api/v1/ues', route => route.fulfill({ json: { items: [shared, owned], configured_profiles: [], configured_count: 4, active_count: 2, registered_count: 2, pdu_session_count: 2, source: 'TEST' } }));
  await page.route('**/api/v1/traffic/status', route => route.fulfill({ json: { state: 'IDLE', packets_requested: 0, packets_sent: null, packets_received: null, bytes: null, accounting_source: 'TEST', last_result: null, approved_destinations: ['10.46.0.1'] } }));
  await page.route('**/api/v1/scenarios/status', route => route.fulfill({ json: { active_job: null, latest_terminal_job: null, active_count: 0, history_count: 0, observed_at_epoch_s: 0, source: 'TEST' } }));
  let validatedTarget = '';
  let startBody: Record<string, string> = {};
  await page.route('**/api/v1/scenarios/validate', async route => {
    validatedTarget = (await route.request().postDataJSON()).target_ue_id;
    await route.fulfill({ json: { valid: true, scenario_type: 'bounded-controller-ue-udp-v1', target_ue_id: validatedTarget } });
  });
  await page.route('**/api/v1/scenarios/start', async route => {
    startBody = await route.request().postDataJSON();
    await route.fulfill({ json: { state: 'RUNNING', ...startBody } });
  });

  await page.goto('/#/traffic?ue=UE-04');
  const selector = page.getByLabel('Target UE');
  await expect(selector).toHaveValue('UE-04');
  await expect(selector.locator('option')).toHaveCount(2);
  await expect(selector.locator('option', { hasText: 'UE-PSEUDONYM-01' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Validate' }).click();
  await expect(page.getByText('Configuration validated for UE-PSEUDONYM-04.')).toBeVisible();
  expect(validatedTarget).toBe('UE-04');
  await page.getByRole('button', { name: 'Start Traffic' }).click();
  expect(startBody.scenario_type).toBe('bounded-controller-ue-udp-v1');
  expect(startBody.target_ue_id).toBe('UE-04');
  expect(startBody).not.toHaveProperty('interface');
  expect(startBody).not.toHaveProperty('command');
  await expect(page.getByText('Traffic job started for UE-PSEUDONYM-04.')).toBeVisible();
});
