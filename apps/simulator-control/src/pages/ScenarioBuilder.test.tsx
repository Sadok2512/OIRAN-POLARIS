// 0.5.1 — Honest Scenario Builder tests.
//
// What this covers:
//   * Palette: counts of clickable (supported) vs locked step chips in
//     backend mode. Reason is surfaced on the locked chip's `title`.
//   * LoopEditor: Infinite / Random / Custom are disabled when backendOnly.
//   * Save: blocked and shows a banner when the current draft holds a
//     non-certified step (e.g. ims_register) in backend mode.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';
import { ScenarioBuilderPage } from './ScenarioBuilder';
import { _resetFlags, setFlag } from '@/data/featureFlags';
import { STEP_METADATA, type ScenarioStepKind } from '@/scenarios/model';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function renderPage(children: ReactNode = <ScenarioBuilderPage />) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  if (typeof localStorage !== 'undefined') localStorage.clear();
  if (typeof sessionStorage !== 'undefined') sessionStorage.clear();
  _resetFlags();
  // 0.5.1 default is ON; be explicit for clarity.
  setFlag('scenarioBackend', true);
  // The library hook fetches /scenario-definitions on mount; stub it so the
  // page renders instantly without hitting the real backend.
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.endsWith('/scenario-definitions')) {
      return respond(200, { items: [], total: 0, schema_version: 1 });
    }
    return respond(404, { error: 'not stubbed' });
  }) as unknown as typeof fetch;
});

afterEach(() => {
  vi.restoreAllMocks();
  _resetFlags();
});

describe('ScenarioBuilder — honest palette (0.5.1)', () => {
  it('exposes exactly 9 backend-certified step chips as clickable and locks the rest with their reason', async () => {
    renderPage();
    // Wait for the hydrated draft.
    await screen.findByTestId('step-palette');

    const certifiedKinds = (Object.keys(STEP_METADATA) as ScenarioStepKind[]).filter(
      (kind) => STEP_METADATA[kind].backendCertified,
    );
    const lockedKinds = (Object.keys(STEP_METADATA) as ScenarioStepKind[]).filter(
      (kind) => !STEP_METADATA[kind].backendCertified,
    );
    // Sanity: 20 kinds total = 9 certified + 11 locked.
    expect(certifiedKinds).toHaveLength(9);
    expect(lockedKinds).toHaveLength(11);

    for (const kind of certifiedKinds) {
      const chip = screen.getByTestId(`add-step-${kind}`);
      expect(chip).toBeEnabled();
    }
    for (const kind of lockedKinds) {
      const chip = screen.getByTestId(`locked-step-${kind}`);
      expect(chip).toHaveAttribute('aria-disabled', 'true');
      // The backendNote shows up verbatim in the chip's `title`.
      const reason = STEP_METADATA[kind].backendNote ?? '';
      if (reason) expect(chip).toHaveAttribute('title', reason);
    }
    // The chip count surfaced in the DOM matches the certified count exactly:
    // "no non-certified chip is clickable" is enforced by the two loops above.
  });

  it('locks Infinite, Random and Custom loop presets when scenarioBackend is ON', async () => {
    renderPage();
    await screen.findByTestId('loop-editor');
    const infinite = screen.getByTestId('loop-preset-infinite');
    const random = screen.getByTestId('loop-preset-random');
    const custom = screen.getByTestId('loop-preset-custom');
    expect(infinite).toBeDisabled();
    expect(random).toBeDisabled();
    expect(custom).toBeDisabled();
    // Once + ×50 + ×100 stay clickable.
    expect(screen.getByTestId('loop-preset-once')).toBeEnabled();
    expect(screen.getByTestId('loop-preset-×50')).toBeEnabled();
    expect(screen.getByTestId('loop-preset-×100')).toBeEnabled();
  });

  it('blocks Save and shows a banner when the draft contains a locked step (ims_register)', async () => {
    const user = userEvent.setup();
    renderPage();

    // Seed a certified step first so the draft passes "at least one step" validation.
    const supported = await screen.findByTestId('add-step-UE_START');
    await user.click(supported);

    // Save button should be enabled now.
    const save = screen.getByTestId('builder-save');
    await waitFor(() => expect(save).toBeEnabled());

    // Inject a non-certified step by changing the newly-added UE_START's
    // kind select to IMS_REGISTER. The kind select appears via StepEditor.
    const kindSelect = (await screen.findByLabelText(/Step 1 kind/i)) as HTMLSelectElement;
    await user.selectOptions(kindSelect, 'IMS_REGISTER');

    // Banner appears and Save is blocked.
    await screen.findByTestId('builder-locked-step-banner');
    expect(save).toBeDisabled();
    expect(save).toHaveAttribute(
      'title',
      'Remove the non-certified step(s) before saving to the backend',
    );
  });

  it('offline-draft mode (flag OFF) hides the locked-step banner and clears the Save guard', async () => {
    setFlag('scenarioBackend', false);
    const user = userEvent.setup();
    renderPage();
    // Supported chips are still rendered; non-certified ones remain in the
    // locked group, but Save no longer blocks on them.
    const supported = await screen.findByTestId('add-step-UE_START');
    await user.click(supported);
    const kindSelect = (await screen.findByLabelText(/Step 1 kind/i)) as HTMLSelectElement;
    await user.selectOptions(kindSelect, 'IMS_REGISTER');
    expect(screen.queryByTestId('builder-locked-step-banner')).toBeNull();
    expect(screen.getByTestId('builder-save')).toBeEnabled();
    expect(screen.getByTestId('builder-offline-draft-badge')).toBeInTheDocument();
  });
});
