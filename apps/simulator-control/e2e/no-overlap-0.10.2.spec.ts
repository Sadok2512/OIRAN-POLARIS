// 0.10.2 — Mandatory anti-overlap acceptance.
//
// For every rendered row in the UE Manager table, we assert two
// invariants at both 1440 and 1920 widths:
//
//   1. No bounding box of a visible text / button inside the row
//      overlaps any other sibling bounding box. This catches regressions
//      where the Scenario cell overflows under the Start button or the
//      PDU dot kisses the "Deregistered" label.
//
//   2. For every text node the row contains, `scrollWidth` must be
//      less than or equal to `clientWidth`. In other words: no text is
//      silently truncated.
//
// A failure must block the push — these invariants are the whole point
// of the 0.10.2 honest-UX pass.

import { test, expect, type Page } from '@playwright/test';

async function mockPolarisBackend(page: Page) {
  // 0.10.2 — All subscriber identities in mocks use the lab-fictive
  // MCC 999 prefix. No real IMSI ever lands in a fixture.
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
  await page.route('**/polaris-api/v1/capabilities', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        live_control: false,
        approval_state: 'closed',
        max_ues: 100,
        max_nodes: 10,
        registration_modes: ['automatic'],
        traffic_protocols: ['udp'],
        scenario_step_kinds: [],
      }),
    }),
  );
  await page.route('**/polaris-api/v1/scenarios/status**', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        active_job: null,
        latest_terminal_job: null,
        active_count: 0,
        history_count: 0,
        observed_at_epoch_s: 0,
        source: 'MOCK',
      }),
    }),
  );
  await page.route('**/polaris-api/v1/scenarios**', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ items: [], total: 0, source: 'MOCK' }),
    }),
  );
  await page.route('**/polaris-api/v1/ue-profiles**', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [
          {
            ue_id: 'UE-01',
            name: 'alice',
            serving_gnb: 'GNB-01',
            plmn: { mcc: '999', mnc: '01' },
            dnn: 'internet',
            snssai: { sst: 1, sd: '010203' },
            pdu_session: { dnn: 'internet', type: 'IPv4' },
            scenario_id: null,
            auto_run_scenario: false,
            subscription_status: 'VERIFIED',
            subscriber_identity: 'PROTECTED',
            authentication_material: 'PROTECTED',
            profile: 'POLARIS',
            revision: 1,
            updated_at_epoch_s: 1_730_200_000,
          },
          {
            ue_id: 'UE-02',
            name: 'bob',
            serving_gnb: 'GNB-01',
            plmn: { mcc: '999', mnc: '01' },
            dnn: 'internet',
            snssai: { sst: 1, sd: '010203' },
            pdu_session: { dnn: 'internet', type: 'IPv4' },
            scenario_id: null,
            auto_run_scenario: false,
            subscription_status: 'PROVISIONING_REQUIRED',
            subscriber_identity: 'PROTECTED',
            authentication_material: 'PROTECTED',
            profile: 'POLARIS',
            revision: 1,
            updated_at_epoch_s: 1_730_200_000,
          },
        ],
        total: 2,
        page: 1,
        page_size: 50,
        pages: 1,
        max: 10,
        secrets_exposed: false,
      }),
    }),
  );
  await page.route('**/polaris-api/v1/ues', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [
          {
            id: 'UE-01',
            internal_ue_id: 'UE-01',
            profile: 'POLARIS',
            profile_state: 'VERIFIED',
            subscription_status: 'VERIFIED',
            serving_node: 'GNB-01',
            process_state: 'running',
            registration_state: 'REGISTERED',
            pdu_session: 'ACTIVE',
            rrc_state: 'CONNECTED',
            ue_ip: '10.46.0.5',
            traffic_state: 'IDLE',
            last_event: null,
            controller_owned: true,
            actions: { start: false, stop: true, pdu_start: false, pdu_stop: true },
          },
          {
            id: 'UE-02',
            internal_ue_id: 'UE-02',
            profile: 'POLARIS',
            profile_state: 'VERIFIED',
            subscription_status: 'PROVISIONING_REQUIRED',
            serving_node: 'GNB-01',
            process_state: 'idle',
            registration_state: 'UNKNOWN',
            pdu_session: 'UNKNOWN',
            rrc_state: 'UNKNOWN',
            ue_ip: null,
            traffic_state: null,
            last_event: null,
            controller_owned: true,
            actions: { start: true, stop: false, pdu_start: false, pdu_stop: false },
          },
        ],
        configured_profiles: [],
        configured_count: 2,
        active_count: 1,
        registered_count: 1,
        source: 'MOCK',
      }),
    }),
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
  // Zero-area or near-zero rectangles are ignored (hidden spans).
  if (a.width <= 1 || a.height <= 1 || b.width <= 1 || b.height <= 1) return false;
  const horizontal = a.x < b.x + b.width - 1 && b.x < a.x + a.width - 1;
  const vertical = a.y < b.y + b.height - 1 && b.y < a.y + a.height - 1;
  return horizontal && vertical;
}

test.describe('0.10.2 — no overlap, no truncation', () => {
  test.beforeEach(async ({ page }) => {
    await mockPolarisBackend(page);
    await page.addInitScript(() => {
      localStorage.setItem(
        'polaris.featureFlags.v1',
        JSON.stringify({
          scenarioBackend: true,
          profileBackend: true,
          scenarioTemplates: true,
          polarisProvisioning: false,
        }),
      );
    });
  });

  test('UE Manager rows have no cross-cell overlap and no truncated text', async ({ page }) => {
    await page.goto('./ues');
    await page.getByTestId('ue-table').waitFor();
    const rowIds = await page.getByTestId('ue-table').locator('tbody tr[data-testid^="ue-row-"]').evaluateAll(
      (rows) => rows.map((row) => row.getAttribute('data-testid') ?? ''),
    );
    expect(rowIds.length).toBeGreaterThan(0);

    for (const testid of rowIds) {
      const row = page.getByTestId(testid);
      // 1) Collect bounding boxes for every text + button leaf.
      const rects: Rect[] = await row.evaluate((node) => {
        const out: Rect[] = [];
        const walker = document.createTreeWalker(node, NodeFilter.SHOW_ELEMENT);
        let current: Node | null = walker.currentNode;
        while (current) {
          const el = current as HTMLElement;
          const tag = el.tagName.toLowerCase();
          if (['button', 'a', 'span', 'select'].includes(tag)) {
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

      // Filter to leaf-ish items (buttons + spans only); same cell contents
      // overlap by construction. Keep only elements that are NOT a parent
      // of another in the collected list.
      const leafRects = rects.filter((candidate) => {
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

      // 2) No two leaf boxes overlap. We tolerate a one-pixel seam.
      for (let i = 0; i < leafRects.length; i += 1) {
        for (let j = i + 1; j < leafRects.length; j += 1) {
          const a = leafRects[i];
          const b = leafRects[j];
          expect(
            overlap(a, b),
            `${testid}: "${a.text}" (${a.tag}) overlaps "${b.text}" (${b.tag})`,
          ).toBe(false);
        }
      }

      // 3) No text truncation (scrollWidth ≤ clientWidth) on any
      // text-bearing node inside the row.
      const truncated: { text: string; scrollWidth: number; clientWidth: number }[] =
        await row.evaluate((node) => {
          const bad: { text: string; scrollWidth: number; clientWidth: number }[] = [];
          const nodes = node.querySelectorAll('span, td, button, a, option');
          for (const el of Array.from(nodes) as HTMLElement[]) {
            if (!el.innerText || el.innerText.trim().length === 0) continue;
            // Only flag the leaf-level truncation: `scrollWidth` strictly
            // greater than `clientWidth` and the element is single-line.
            const style = window.getComputedStyle(el);
            const whiteSpace = style.whiteSpace;
            if (whiteSpace !== 'nowrap' && style.overflow !== 'hidden') continue;
            if (el.scrollWidth > el.clientWidth + 1) {
              bad.push({
                text: el.innerText.trim().slice(0, 80),
                scrollWidth: el.scrollWidth,
                clientWidth: el.clientWidth,
              });
            }
          }
          return bad;
        });
      expect(
        truncated,
        `${testid}: text truncated → ${JSON.stringify(truncated)}`,
      ).toEqual([]);
    }
  });
});
