// Execution Monitor captures (simulator-control 0.9.0 + polaris-control-api
// 0.17.0 enriched /scenarios/:job_id/steps).
//
// Mocked API — no live POLARIS. Identity fields always render PROTECTED.

import { test, expect, type Page } from '@playwright/test';

const JOB_ID = 'job-protected-001';

async function mockApi(page: Page) {
  await page.route('**/polaris-api/v1/auth/me', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ role: 'OPERATOR', can_start: true }),
    }),
  );

  await page.route('**/polaris-api/v1/scenarios/status', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        active_job: null,
        latest_terminal_job: {
          job_id: JOB_ID,
          scenario_id: 'traffic_dl_1mb',
          technology: 'NR',
          simulator: 'POLARIS',
          state: 'FAILED',
          target_ue_id: 'UE-01',
          started_at: '2026-10-29T10:00:00Z',
          duration_seconds: 42,
          registered_ues: 1,
          active_pdu_sessions: 1,
          traffic_state: 'IDLE',
          packets_sent: 0,
          packets_requested: 0,
          cpu: 'OK',
          memory: 'OK',
          terminal_result: 'STEP_FAILED',
          controller_owned: true,
        },
      }),
    }),
  );

  await page.route('**/polaris-api/v1/traffic/status', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        state: 'IDLE',
        packets_requested: 0,
        packets_sent: 0,
        packets_received: 0,
        bytes: 0,
        accounting_source: 'PROTECTED',
        target_ue_id: 'UE-01',
        target_ue_pseudonym: 'PROTECTED',
        tun_interface: 'uesimtun0',
        last_result: null,
        approved_destinations: ['10.46.0.1'],
      }),
    }),
  );

  await page.route(`**/polaris-api/v1/scenarios/${JOB_ID}/steps`, (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        job_id: JOB_ID,
        scenario_definition_id: 'traffic_dl_1mb',
        state: 'FAILED',
        started_at: 1_730_200_000,
        ended_at: 1_730_200_042,
        duration_ms: 42_000,
        steps: [
          {
            index: 0,
            type: 'TRAFFIC_DL',
            state: 'FAILED',
            scenario_loop: { count: 1, iteration: 1 },
            step_loop: { count: 1, iteration: 1 },
            started_at: 1_730_200_001,
            ended_at: 1_730_200_042,
            error: 'DL_SENDER_NOT_AVAILABLE',
            resolved_parameters: {},
          },
        ],
        failure: {
          step_id: 0,
          step_name: 'TRAFFIC_DL',
          code: 'DL_SENDER_NOT_AVAILABLE',
          message: 'DN sender container is not healthy',
          failure_evidence: {
            command: 'iperf3 -c 10.77.24.30 -b 1M -t 10',
            exit_code: 1,
            stderr: 'unable to connect to server',
          },
          started_at: 1_730_200_001,
          ended_at: 1_730_200_042,
          duration_ms: 41_000,
        },
      }),
    }),
  );
}

test.describe('execution monitor', () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page);
  });

  test('failed job surfaces step name, code, message, duration and failure_evidence', async ({ page }) => {
    await page.goto('/#/execution-monitor');
    await expect(page.getByTestId('backend-steps')).toBeVisible();
    await expect(page.getByTestId('backend-steps-state')).toHaveText(/FAILED/);
    await expect(page.getByTestId('backend-steps-duration')).toContainText(/s/);

    const failure = page.getByTestId('backend-steps-failure');
    await expect(failure).toBeVisible();
    await expect(failure).toContainText('DL_SENDER_NOT_AVAILABLE');
    await expect(failure).toContainText('TRAFFIC_DL');
    await expect(page.getByTestId('backend-steps-failure-message')).toContainText('DN sender');

    await page.getByText('failure_evidence (bounded)').click();
    const evidence = page.getByTestId('backend-steps-failure-evidence');
    await expect(evidence).toContainText('exit_code');

    await page.screenshot({
      path: 'docs/screenshots/execution-monitor-failed.png',
      fullPage: true,
    });
  });
});
