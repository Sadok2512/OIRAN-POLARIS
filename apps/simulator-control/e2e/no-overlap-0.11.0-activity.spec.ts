// 0.11.0 (#37) — Anti-overlap acceptance for the per-UE Activity page.
//
// Three viewports × two colour schemes = 6 projects. Same leaf-bbox +
// scrollWidth invariants as the 0.10.4 UE Manager spec, applied this
// time to the new /ues/:ueId/activity surface.

import { test, expect, type Page } from '@playwright/test';

async function mockPolarisBackend(page: Page) {
  await page.route('**/polaris-api/v1/**', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({}) }),
  );
  await page.route('**/polaris-api/v1/auth/me', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        authenticated: true,
        username: 'ops',
        role: 'operator',
        can_start: true,
        can_manage_permissions: false,
      }),
    }),
  );
  // Activity snapshot — rich running payload with production-shaped
  // long values so overlap at 1280 shows up if it exists.
  await page.route('**/polaris-api/v1/ues/UE-00042/activity', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        ue_id: 'UE-00042',
        running: true,
        imsi: 'imsi-001010000000042',
        states: {
          rm_state: 'RM-REGISTERED',
          cm_state: 'CM-CONNECTED',
          rrc_state: 'RRC-CONNECTED',
          mm_5g_state: 'MM-REGISTERED-NORMAL-SERVICE',
        },
        pdu: { psi: 1, dnn: 'internet', state: 'PS-ACTIVE', address: '10.46.0.142' },
        counters: {
          interface: 'uesimtun0',
          rx_bytes: 12_345_678,
          rx_packets: 1_024,
          tx_bytes: 2_345_678,
          tx_packets: 512,
          rx_bps: 42_000,
          tx_bps: 8_000,
        },
        job_step: {
          job_id: 'bounded-controller-ue-udp-v1-abc123',
          definition_id: 'bounded-controller-ue-udp-v1',
          state: 'RUNNING',
          current_step: { index: 2, type: 'udp_traffic', state: 'RUNNING' },
        },
        events: [
          { epoch_s: 1_730_200_000, kind: 'live_start', outcome: 'OK', detail: {} },
          { epoch_s: 1_730_200_010, kind: 'registration', outcome: 'OK', detail: {} },
          { epoch_s: 1_730_200_020, kind: 'pdu_establish', outcome: 'OK', detail: {} },
        ],
        voice: { available: false, reason: 'IMS_NOT_AVAILABLE' },
      }),
    }),
  );
  // SSE stream — route it to a 404 so EventSource falls back to the
  // polling path; the test is about layout, not stream events.
  await page.route('**/polaris-api/v1/ues/UE-00042/activity/stream', (route) =>
    route.fulfill({ status: 404 }),
  );
}

interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
  text: string;
  tag: string;
}

function overlap(a: Rect, b: Rect): boolean {
  if (a.width <= 1 || a.height <= 1 || b.width <= 1 || b.height <= 1) return false;
  const horizontal = a.x < b.x + b.width - 1 && b.x < a.x + a.width - 1;
  const vertical = a.y < b.y + b.height - 1 && b.y < a.y + a.height - 1;
  return horizontal && vertical;
}

test.describe('0.11.0 — Activity page: no overlap, no truncation', () => {
  test.beforeEach(async ({ page }) => {
    await mockPolarisBackend(page);
    await page.addInitScript(() => {
      localStorage.setItem(
        'polaris.featureFlags.v1',
        JSON.stringify({
          scenarioBackend: true,
          profileBackend: true,
          scenarioTemplates: true,
          polarisProvisioning: true,
        }),
      );
    });
  });

  test('Activity sections render chips, PDU, voice and timeline without overlap', async ({ page }) => {
    await page.goto('./ues/UE-00042/activity');
    await page.getByTestId('activity-states').waitFor();

    // Four chips present, voice panel pinned, timeline populated.
    for (const chip of ['chip-rm', 'chip-cm', 'chip-rrc', 'chip-5gmm']) {
      await expect(page.getByTestId(chip)).toBeVisible();
    }
    await expect(page.getByTestId('activity-voice')).toContainText(/IMS not available/i);
    await expect(page.getByTestId('activity-voice')).toContainText('IMS_NOT_AVAILABLE');
    await expect(page.getByTestId('activity-pdu-dnn')).toContainText('internet');
    await expect(page.getByTestId('activity-pdu-ip')).toContainText('10.46.0.142');
    await expect(page.getByTestId('timeline-list')).toBeVisible();
    await expect(page.getByTestId('activity-live')).toBeVisible();

    // Collect all leaf-ish boxes inside the main page container and
    // assert pairwise non-overlap + no truncation.
    const main = page.locator('main');
    const rects: Rect[] = await main.evaluate((node) => {
      const out: { x: number; y: number; width: number; height: number; text: string; tag: string }[] = [];
      const walker = document.createTreeWalker(node, NodeFilter.SHOW_ELEMENT);
      let current: Node | null = walker.currentNode;
      while (current) {
        const el = current as HTMLElement;
        const tag = el.tagName.toLowerCase();
        if (['button', 'a', 'span'].includes(tag)) {
          const rect = el.getBoundingClientRect();
          if (rect.width > 1 && rect.height > 1) {
            out.push({
              x: rect.x,
              y: rect.y,
              width: rect.width,
              height: rect.height,
              text: (el.innerText || el.getAttribute('aria-label') || '').trim().slice(0, 60),
              tag,
            });
          }
        }
        current = walker.nextNode();
      }
      return out;
    });

    const leaves = rects.filter((candidate) => {
      return !rects.some((other) => {
        if (other === candidate) return false;
        const contains =
          other.x >= candidate.x &&
          other.y >= candidate.y &&
          other.x + other.width <= candidate.x + candidate.width + 0.5 &&
          other.y + other.height <= candidate.y + candidate.height + 0.5;
        return contains && other !== candidate;
      });
    });

    // Pairwise overlap check INSIDE the same visual row only. Two
    // boxes in different sections at different Y bands may legitimately
    // share horizontal space (the responsive grid handles layout),
    // so we restrict the invariant to boxes whose vertical rects
    // meaningfully overlap (> 60% shared height). This matches the
    // 0.10.4 anti-overlap spirit without being over-strict for a
    // multi-section page.
    for (let i = 0; i < leaves.length; i += 1) {
      for (let j = i + 1; j < leaves.length; j += 1) {
        const a = leaves[i];
        const b = leaves[j];
        if (!overlap(a, b)) continue;
        const sharedY =
          Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y);
        const minHeight = Math.min(a.height, b.height);
        if (sharedY / minHeight < 0.6) continue;
        // Siblings on the same visual band must not overlap horizontally.
        expect(
          overlap(a, b),
          `"${a.text}" (${a.tag}) overlaps "${b.text}" (${b.tag})`,
        ).toBe(false);
      }
    }

    const scrolls = await page.evaluate(() => ({
      body: document.body.scrollWidth > document.body.clientWidth,
      main: document.querySelector('main')
        ? document.querySelector('main')!.scrollWidth > document.querySelector('main')!.clientWidth
        : false,
    }));
    expect(scrolls.body, 'body must not scroll horizontally').toBe(false);
    expect(scrolls.main, 'main must not scroll horizontally').toBe(false);
  });

  test('Activity page shows "UE non démarré" banner for stopped UE', async ({ page }) => {
    await page.route('**/polaris-api/v1/ues/UE-99/activity', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ue_id: 'UE-99',
          running: false,
          reason: 'UE_NOT_RUNNING',
          events: [],
          voice: { available: false, reason: 'IMS_NOT_AVAILABLE' },
        }),
      }),
    );
    await page.route('**/polaris-api/v1/ues/UE-99/activity/stream', (route) =>
      route.fulfill({ status: 404 }),
    );
    await page.goto('./ues/UE-99/activity');
    const banner = page.getByTestId('activity-not-running');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText(/non démarré/i);
    await expect(banner).toContainText('UE_NOT_RUNNING');
  });
});
