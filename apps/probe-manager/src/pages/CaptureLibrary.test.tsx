import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from '@/test/testUtils';
import { CaptureLibraryPage } from './CaptureLibrary';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const CAPTURES = [
  {
    capture_id: 'sha256:aa',
    name: 'historical-ng-c',
    probe_id: 'probe-01',
    interface: 'N2',
    protocol: 'NGAP',
    state: 'COMPLETED',
    dataset_id: 'ds-1',
    metrics: {
      packets_received: 100,
      bytes_received: 10_000,
      packets_per_second: 10,
      bits_per_second: 80_000,
      decoded_events: 20,
      decode_errors: 0,
      packet_drops: 0,
      storage_bytes: 10_000,
    },
  },
  {
    capture_id: 'sha256:bb',
    name: 'live-sbi',
    probe_id: 'probe-02',
    interface: 'SBI',
    protocol: 'HTTP/2',
    state: 'CAPTURING',
    dataset_id: null,
  },
];

describe('Capture Library', () => {
  function stubFetch(captures: unknown[] = CAPTURES) {
    globalThis.fetch = vi.fn(async (input) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/captures')) {
        return respond(200, { data: captures, meta: { total: captures.length } });
      }
      return respond(200, { data: [], meta: {} });
    }) as unknown as typeof fetch;
  }

  it('renders every column header required by the design brief', async () => {
    stubFetch();
    render(renderWithProviders(<CaptureLibraryPage />));
    const table = await screen.findByTestId('capture-table');
    expect(within(table).getByText('Capture name')).toBeInTheDocument();
    expect(within(table).getByText('Probe')).toBeInTheDocument();
    expect(within(table).getByText('Interfaces')).toBeInTheDocument();
    expect(within(table).getByText('Protocol')).toBeInTheDocument();
    expect(within(table).getByText('Start time')).toBeInTheDocument();
    expect(within(table).getByText('Duration')).toBeInTheDocument();
    expect(within(table).getByText('Packets')).toBeInTheDocument();
    expect(within(table).getByText('Size')).toBeInTheDocument();
    expect(within(table).getByText('Status')).toBeInTheDocument();
    expect(within(table).getByText('Dataset')).toBeInTheDocument();
    expect(within(table).getByText('Actions')).toBeInTheDocument();
  });

  it('filters captures by text search', async () => {
    stubFetch();
    const user = userEvent.setup();
    render(renderWithProviders(<CaptureLibraryPage />));
    await waitFor(() =>
      expect(screen.getByText('historical-ng-c')).toBeInTheDocument(),
    );
    await user.type(screen.getByTestId('capture-search'), 'sbi');
    await waitFor(() =>
      expect(screen.queryByText('historical-ng-c')).not.toBeInTheDocument(),
    );
    expect(screen.getByText('live-sbi')).toBeInTheDocument();
  });

  it('renders an empty state when the backend returns no captures', async () => {
    stubFetch([]);
    render(renderWithProviders(<CaptureLibraryPage />));
    await waitFor(() =>
      expect(screen.getByTestId('empty-state')).toBeInTheDocument(),
    );
  });

  it('disables the Analyzer action when the capture has no dataset_id', async () => {
    stubFetch();
    render(renderWithProviders(<CaptureLibraryPage />));
    await waitFor(() => expect(screen.getByText('live-sbi')).toBeInTheDocument());
    const row = screen.getByText('live-sbi').closest('tr')!;
    const analyzer = within(row).getByText('Analyzer');
    expect(analyzer.closest('button')).toBeDisabled();
  });
});
