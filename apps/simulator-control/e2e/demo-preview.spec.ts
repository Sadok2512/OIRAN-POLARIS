import { mkdirSync } from 'node:fs';
import { expect, test } from '@playwright/test';

test.skip(process.env.POLARIS_DEMO_MODE !== '1', 'Dedicated local DEMO preview only');

const captureProject = (name: string) =>
  name === 'chromium-1440-light' || name === 'chromium-1440-dark';

test('DEMO preview exposes LTE/5G pages read-only without horizontal overflow', async ({ page }, testInfo) => {
  await page.goto('./ues');
  await expect(page.getByTestId('demo-read-only-banner')).toContainText('DEMO SYNTHÉTIQUE');
  await page.getByTestId('technology-lte').click();
  await expect(page.getByTestId('lte-control-panel')).toContainText('LTE 4G — srsRAN');
  await expect(page.getByRole('button', { name: 'Start LTE certified run' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Stop srsUE' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Stop srsENB' })).toBeDisabled();
  await expectNoOverflow(page);
  if (captureProject(testInfo.project.name)) await capture(page, testInfo.project.name, 'ue-manager-lte');

  await page.goto('./network/topology');
  await expect(page.getByTestId('topology-chain-5g')).toContainText('Open5GS 5GC');
  await expect(page.getByTestId('topology-chain-5g')).toContainText('UERANSIM gNB');
  await expect(page.getByTestId('topology-chain-5g')).toContainText('UERANSIM UE');
  await expect(page.getByTestId('topology-chain-lte')).toContainText('Open5GS EPC');
  await expect(page.getByTestId('topology-chain-lte')).toContainText('srsENB');
  await expect(page.getByTestId('topology-chain-lte')).toContainText('srsUE');
  await expect(page.getByTestId('topology-link-S1-MME · S1AP')).toHaveAttribute('data-state', 'configured');
  await expect(page.getByTestId('topology-link-S1-U · GTP-U')).toHaveAttribute('data-state', 'configured');
  await expect(page.getByTestId('topology-link-N2 · NGAP')).toHaveAttribute('data-state', 'configured');
  await expect(page.getByTestId('topology-link-N3 · GTP-U')).toHaveAttribute('data-state', 'configured');
  await expectNoOverflow(page);
  if (captureProject(testInfo.project.name)) await capture(page, testInfo.project.name, 'topology-lte-5g');

  await page.goto('./scenarios/new');
  await page.getByTestId('technology-lte').click();
  await expect(page.getByText(/Live requires ANR1 LTE E2E certification/)).toBeVisible();
  await expectNoOverflow(page);
  if (captureProject(testInfo.project.name)) await capture(page, testInfo.project.name, 'scenario-builder-lte');

  await page.goto('./network/gnbs');
  await expect(page.getByRole('heading', { name: 'ENB-DEMO-01' })).toBeVisible();
  await expect(page.getByText('srsRAN · LTE')).toBeVisible();
  await expectNoOverflow(page);
  if (captureProject(testInfo.project.name)) await capture(page, testInfo.project.name, 'simulator-control');

  await page.goto('./traffic/sessions');
  await page.getByTestId('technology-lte').click();
  await expect(page.getByRole('button', { name: 'LTE traffic locked' })).toBeDisabled();
  await expect(page.getByTestId('traffic-session-traffic-demo-lte')).toBeVisible();
  await expect(page.getByTestId('traffic-session-traffic-demo-5g')).toBeVisible();
  await expectNoOverflow(page);
  if (captureProject(testInfo.project.name)) await capture(page, testInfo.project.name, 'traffic-generator');
});

async function expectNoOverflow(page: import('@playwright/test').Page) {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(overflow).toBe(false);
}

async function capture(
  page: import('@playwright/test').Page,
  project: string,
  name: string,
) {
  const directory = `docs/preview/${project}`;
  mkdirSync(directory, { recursive: true });
  await page.screenshot({ path: `${directory}/${name}.png`, fullPage: true });
}
