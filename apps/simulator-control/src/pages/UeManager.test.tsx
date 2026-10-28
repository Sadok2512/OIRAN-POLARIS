import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { UeManagerPage } from './UeManager';
import { _resetProfiles, _seedProfiles } from '@/ue/profileStore';
import { _resetFlags, setFlag } from '@/data/featureFlags';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function stubFetch(role: 'viewer' | 'operator' = 'operator') {
  const authBody = {
    data: {
      authenticated: role === 'operator',
      username: role === 'operator' ? 'ops' : null,
      role,
      can_start: role === 'operator',
      can_manage_permissions: false,
    },
    meta: {},
  };
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/auth/me')) return respond(200, authBody);
    if (url.includes('/scenarios/status'))
      return respond(200, {
        data: {
          active_job: null,
          latest_terminal_job: null,
          active_count: 0,
          history_count: 0,
          observed_at_epoch_s: 0,
          source: 'test',
        },
        meta: {},
      });
    if (url.includes('/ues'))
      return respond(200, {
        data: {
          items: [],
          configured_profiles: [],
          configured_count: 0,
          active_count: 0,
          registered_count: 0,
          source: 'test',
        },
        meta: {},
      });
    return respond(200, { data: {}, meta: {} });
  }) as unknown as typeof fetch;
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <UeManagerPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  if (typeof localStorage !== 'undefined') localStorage.clear();
  _resetFlags();
  setFlag('polarisProvisioning', false);
  _resetProfiles();
  stubFetch('operator');
});

afterEach(() => {
  vi.restoreAllMocks();
  _resetFlags();
  _resetProfiles();
});

describe('UE Profile Manager — add / edit / delete', () => {
  it('shows an empty state when no profile is stored', async () => {
    renderPage();
    expect(await screen.findByTestId('ue-table')).toBeInTheDocument();
    expect(screen.getByText(/No UE profile yet/i)).toBeInTheDocument();
  });

  it('adds a profile through the dialog', async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByTestId('ue-add'));
    await user.type(screen.getByTestId('profile-field-id'), 'ue-manual');
    await user.type(screen.getByTestId('profile-field-owner'), 'alice');
    await user.type(screen.getByTestId('profile-field-servingGnb'), 'gnb-01');
    await user.click(screen.getByTestId('profile-form-submit'));
    await waitFor(() => expect(screen.getByTestId('ue-row-ue-manual')).toBeInTheDocument());
    expect(screen.getByTestId('ue-feedback')).toHaveTextContent(/created/i);
  });

  it('edits a profile in place', async () => {
    _seedProfiles([
      {
        id: 'ue-1',
        owner: 'alice',
        servingGnb: 'gnb-01',
        createdAt: 1,
        updatedAt: 1,
      },
    ]);
    renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByTestId('ue-edit-ue-1'));
    const notesInput = screen.getAllByRole('textbox').find((element) =>
      (element as HTMLInputElement).parentElement?.textContent?.toLowerCase().includes('notes'),
    );
    expect(notesInput).toBeDefined();
    await user.type(notesInput as HTMLInputElement, 'important');
    await user.click(screen.getByTestId('profile-form-submit'));
    await waitFor(() => expect(screen.getByTestId('ue-feedback')).toHaveTextContent(/updated/i));
  });

  it('deletes a profile after confirmation', async () => {
    _seedProfiles([
      {
        id: 'ue-del',
        owner: 'alice',
        servingGnb: 'gnb-01',
        createdAt: 1,
        updatedAt: 1,
      },
    ]);
    renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByTestId('ue-delete-ue-del'));
    await user.click(screen.getByTestId('confirm-dialog-confirm'));
    await waitFor(() =>
      expect(screen.queryByTestId('ue-row-ue-del')).not.toBeInTheDocument(),
    );
  });
});

describe('UE Profile Manager — pagination at 10K', () => {
  it('renders page 1 of 200 for a 10,000-profile store without instantiating every row', async () => {
    const now = Date.now();
    _seedProfiles(
      Array.from({ length: 10_000 }, (_, index) => ({
        id: `ue-${(index + 1).toString().padStart(5, '0')}`,
        owner: index % 2 === 0 ? 'alice' : 'bob',
        servingGnb: `gnb-${(index % 10).toString().padStart(2, '0')}`,
        createdAt: now - index,
        updatedAt: now - index,
      })),
    );
    renderPage();
    const table = await screen.findByTestId('ue-table');
    const rows = within(table).getAllByRole('row');
    // 1 header row + 50 body rows (default page size)
    expect(rows.length).toBeLessThanOrEqual(51);
    expect(await screen.findByTestId('ue-pagination')).toHaveTextContent(/1 \/ 200/);
    expect(screen.getByText(/10,000/)).toBeInTheDocument();
  });

  it('navigates between pages', async () => {
    const now = Date.now();
    _seedProfiles(
      Array.from({ length: 200 }, (_, index) => ({
        id: `ue-${(index + 1).toString().padStart(4, '0')}`,
        owner: 'alice',
        servingGnb: 'gnb-01',
        createdAt: now,
        updatedAt: now,
      })),
    );
    renderPage();
    const user = userEvent.setup();
    expect(await screen.findByTestId('ue-row-ue-0001')).toBeInTheDocument();
    await user.click(screen.getByTestId('ue-page-next'));
    await waitFor(() => expect(screen.queryByTestId('ue-row-ue-0001')).not.toBeInTheDocument());
    expect(screen.getByTestId('ue-row-ue-0051')).toBeInTheDocument();
  });

  it('filters by search without exploding the DOM at 10K scale', async () => {
    const now = Date.now();
    _seedProfiles(
      Array.from({ length: 10_000 }, (_, index) => ({
        id: `ue-${(index + 1).toString().padStart(5, '0')}`,
        owner: index % 2 === 0 ? 'alice' : 'bob',
        servingGnb: `gnb-${(index % 10).toString().padStart(2, '0')}`,
        createdAt: now - index,
        updatedAt: now - index,
      })),
    );
    renderPage();
    const user = userEvent.setup();
    await user.type(await screen.findByTestId('ue-search'), 'ue-00042');
    await waitFor(() => {
      const rows = within(screen.getByTestId('ue-table')).getAllByRole('row');
      expect(rows.length).toBe(2); // header + 1 match
    });
    expect(screen.getByTestId('ue-row-ue-00042')).toBeInTheDocument();
  });
});

describe('UE Profile Manager — role-based controls', () => {
  it('disables mutating controls for viewer', async () => {
    stubFetch('viewer');
    renderPage();
    const addButton = await screen.findByTestId('ue-add');
    expect(addButton).toBeDisabled();
    expect(screen.getByTestId('ue-bulk')).toBeDisabled();
    expect(screen.getByTestId('ue-import')).toBeDisabled();
  });
});
