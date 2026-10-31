import { expect, test } from '@playwright/test';

test.skip(process.env.POLARIS_DEMO_MODE !== '1', 'Dedicated local DEMO preview only');

test('Topology visibly keeps srsENB and srsUE beside the UERANSIM 5G chain', async ({ page }) => {
  await page.goto('./network/topology');

  const lte = page.getByTestId('topology-chain-lte');
  const fiveG = page.getByTestId('topology-chain-5g');

  await expect(lte).toContainText('Open5GS EPC');
  await expect(lte).toContainText('srsENB');
  await expect(lte).toContainText('srsUE');
  await expect(lte.getByTestId('topology-link-S1-MME · S1AP')).toHaveAttribute('data-state', 'configured');
  await expect(lte.getByTestId('topology-link-S1-U · GTP-U')).toHaveAttribute('data-state', 'configured');

  await expect(fiveG).toContainText('Open5GS 5GC');
  await expect(fiveG).toContainText('UERANSIM gNB');
  await expect(fiveG).toContainText('UERANSIM UE');
  await expect(fiveG.getByTestId('topology-link-N2 · NGAP')).toHaveAttribute('data-state', 'configured');
  await expect(fiveG.getByTestId('topology-link-N3 · GTP-U')).toHaveAttribute('data-state', 'configured');

  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(overflow).toBe(false);
});
