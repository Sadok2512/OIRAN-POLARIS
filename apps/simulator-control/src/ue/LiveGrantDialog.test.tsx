// 0.11.1 (#46) — "Autoriser le live" dialog component test.
//
// Covers:
//   * The duration preset group defaults to 30 min and switches on
//     click.
//   * The UE checkbox grid honours `defaultSelectedUeIds` and lets
//     the operator toggle items.
//   * Submit POSTs /live/grant with the selected ue_ids and
//     duration, and surfaces the backend error code verbatim on
//     a 422 refusal.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { LiveGrantDialog } from './LiveGrantDialog';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

interface Call {
  method: string;
  url: string;
  body: unknown;
}

function stubFetch(handler: (call: Call) => Response) {
  const calls: Call[] = [];
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    const call = { method, url, body };
    calls.push(call);
    return handler(call);
  }) as unknown as typeof fetch;
  return calls;
}

function renderDialog(props: Partial<React.ComponentProps<typeof LiveGrantDialog>> = {}) {
  const client = new QueryClient({
    defaultOptions: { mutations: { retry: false }, queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <LiveGrantDialog
        open
        availableUeIds={['UE-02', 'UE-03', 'UE-04']}
        onClose={() => undefined}
        {...props}
      />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  if (typeof sessionStorage !== 'undefined') sessionStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('LiveGrantDialog (0.11.1)', () => {
  it('defaults to 30 min and seeds a single UE selection', () => {
    renderDialog();
    expect(screen.getByTestId('live-grant-duration-30')).toHaveAttribute(
      'aria-checked',
      'true',
    );
    // First UE from the list is seeded as the sole selection.
    expect(screen.getByTestId('live-grant-ue-UE-02')).toBeChecked();
    expect(screen.getByTestId('live-grant-ue-UE-03')).not.toBeChecked();
  });

  it('honours defaultSelectedUeIds when supplied (423 Run shortcut)', () => {
    renderDialog({ defaultSelectedUeIds: ['UE-04'] });
    expect(screen.getByTestId('live-grant-ue-UE-02')).not.toBeChecked();
    expect(screen.getByTestId('live-grant-ue-UE-04')).toBeChecked();
  });

  it('POSTs the selected ue_ids and duration, then invokes onCreated', async () => {
    const calls = stubFetch((call) => {
      if (call.method === 'POST' && call.url.endsWith('/live/grant')) {
        return respond(201, {
          id: 'grant-xyz',
          ue_ids: call.body
            ? (call.body as Record<string, unknown>).ue_ids
            : [],
          duration_minutes: 60,
          granted_at_epoch_ms: 1,
          expires_at_epoch_ms: 2,
          granted_by: 'ops',
          revoked: false,
        });
      }
      return respond(404, { error: 'not stubbed' });
    });
    const onCreated = vi.fn();
    const user = userEvent.setup();
    renderDialog({ onCreated });
    await user.click(screen.getByTestId('live-grant-duration-60'));
    await user.click(screen.getByTestId('live-grant-ue-UE-03'));
    await user.click(screen.getByTestId('live-grant-submit'));
    await waitFor(() => expect(onCreated).toHaveBeenCalledWith('grant-xyz'));
    const post = calls.find((call) => call.method === 'POST' && call.url.endsWith('/live/grant'));
    expect(post?.body).toEqual({ ue_ids: ['UE-02', 'UE-03'], duration_minutes: 60 });
  });

  it('surfaces 422 LIVE_GRANT_DURATION_INVALID verbatim', async () => {
    stubFetch((call) => {
      if (call.method === 'POST' && call.url.endsWith('/live/grant')) {
        return respond(422, {
          error: { code: 'LIVE_GRANT_DURATION_INVALID', message: 'bad duration' },
        });
      }
      return respond(404, { error: 'not stubbed' });
    });
    const user = userEvent.setup();
    renderDialog();
    await user.click(screen.getByTestId('live-grant-submit'));
    const banner = await screen.findByTestId('live-grant-error');
    expect(banner).toHaveTextContent(/LIVE_GRANT_DURATION_INVALID/);
    expect(banner).toHaveTextContent(/Durée invalide/i);
  });
});
