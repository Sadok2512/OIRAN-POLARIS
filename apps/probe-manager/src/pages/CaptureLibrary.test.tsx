import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
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

type Capture = {
  capture_id: string;
  name: string;
  probe_id?: string | null;
  interface?: string;
  interfaces?: string[];
  protocol?: string;
  state?: string;
  dataset_id?: string | null;
  size_bytes?: number;
  metrics?: Record<string, number>;
};

const CAPTURES: Capture[] = [
  {
    capture_id: 'sha256:aa',
    name: 'historical-ng-c',
    probe_id: 'probe-01',
    interface: 'N2',
    protocol: 'NGAP',
    state: 'COMPLETED',
    dataset_id: 'ds-1',
    size_bytes: 10_000,
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

function parsePaginationFromUrl(url: string) {
  const u = new URL(url, 'http://x');
  return {
    page: Number(u.searchParams.get('page') ?? '1'),
    pageSize: Number(u.searchParams.get('page_size') ?? '0'),
  };
}

function makePaginatedCaptures(total: number): Capture[] {
  return Array.from({ length: total }, (_, i) => ({
    capture_id: `sha256:${String(i).padStart(4, '0')}`,
    name: `cap-${String(i).padStart(4, '0')}`,
    probe_id: 'probe-01',
    interface: 'N2',
    protocol: 'NGAP',
    state: 'COMPLETED',
    dataset_id: `ds-${i}`,
    size_bytes: 1_000,
  }));
}

type FetchResponder = (url: string) => Response;

function installFetch(responder: FetchResponder) {
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) =>
    responder(typeof input === 'string' ? input : input.toString()),
  ) as unknown as typeof fetch;
}

/**
 * Standard fetch stub that distinguishes `/captures`, `/probes`,
 * `/interfaces` and `/auth/me` so the UI dropdowns do not accidentally
 * surface capture labels (which would make `getByText` ambiguous).
 */
function stubBackend(options: {
  captures?: Capture[];
  total?: number;
  totalPages?: number;
  authenticated?: boolean;
  captureCountOverride?: FetchResponder;
}) {
  const {
    captures = CAPTURES,
    total = captures.length,
    totalPages = 1,
    authenticated = false,
    captureCountOverride,
  } = options;
  installFetch((url) => {
    if (captureCountOverride) {
      const override = captureCountOverride(url);
      if (override) return override;
    }
    if (url.includes('/captures?')) {
      return respond(200, {
        data: captures,
        meta: { total, total_pages: totalPages, page: 1 },
      });
    }
    if (url.includes('/probes')) {
      return respond(200, { data: [], meta: { total: 0 } });
    }
    if (url.includes('/interfaces')) {
      return respond(200, { data: [], meta: { total: 0 } });
    }
    if (url.includes('/auth/me')) {
      return respond(200, {
        data: {
          authenticated,
          role: authenticated ? 'operator' : 'viewer',
          permissions: authenticated ? ['capture.read'] : [],
          capture_control: authenticated,
          capture_execution_enabled: authenticated,
          reason: authenticated ? 'OK' : 'VIEWER',
        },
        meta: {},
      });
    }
    return respond(200, { data: [], meta: {} });
  });
}

beforeEach(() => {
  if (typeof sessionStorage !== 'undefined') sessionStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Capture Library — columns + filters', () => {
  it('renders every column header required by the design brief', async () => {
    stubBackend({});
    render(renderWithProviders(<CaptureLibraryPage />));
    const table = await screen.findByTestId('capture-table');
    for (const header of [
      'Capture name',
      'Probe',
      'Interfaces',
      'Protocol',
      'Start time',
      'Duration',
      'Packets',
      'Size',
      'Status',
      'Dataset',
      'Actions',
    ]) {
      expect(within(table).getByText(header)).toBeInTheDocument();
    }
  });

  it('filters captures by text search', async () => {
    stubBackend({});
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
    stubBackend({ captures: [], total: 0 });
    render(renderWithProviders(<CaptureLibraryPage />));
    await waitFor(() =>
      expect(screen.getByTestId('empty-state')).toBeInTheDocument(),
    );
  });
});

describe('Capture Library — actions (PR #2 Section 5)', () => {
  it('disables Analyzer when the capture has no dataset_id', async () => {
    stubBackend({});
    render(renderWithProviders(<CaptureLibraryPage />));
    await waitFor(() => expect(screen.getByText('live-sbi')).toBeInTheDocument());
    const analyzer = screen.getByTestId('analyzer-sha256:bb');
    expect(analyzer.tagName).toBe('BUTTON');
    expect(analyzer).toBeDisabled();
  });

  it('preserves capture_id and dataset_id in the Analyzer URL', async () => {
    stubBackend({});
    render(renderWithProviders(<CaptureLibraryPage />));
    await waitFor(() =>
      expect(screen.getByText('historical-ng-c')).toBeInTheDocument(),
    );
    const analyzer = screen.getByTestId('analyzer-sha256:aa');
    expect(analyzer).toHaveAttribute('href');
    const url = analyzer.getAttribute('href')!;
    expect(url).toContain('capture_id=sha256%3Aaa');
    expect(url).toContain('dataset_id=ds-1');
  });

  it('disables Download when the user is not authenticated', async () => {
    stubBackend({ authenticated: false });
    render(renderWithProviders(<CaptureLibraryPage />));
    await waitFor(() =>
      expect(screen.getByText('historical-ng-c')).toBeInTheDocument(),
    );
    const download = screen.getByTestId('download-sha256:aa');
    expect(download.tagName).toBe('BUTTON');
    expect(download).toBeDisabled();
  });

  it('enables Download when authenticated AND capture has size', async () => {
    stubBackend({ authenticated: true });
    render(renderWithProviders(<CaptureLibraryPage />));
    await waitFor(() => {
      const download = screen.getByTestId('download-sha256:aa');
      expect(download.tagName).toBe('A');
      expect(download).toHaveAttribute(
        'href',
        '/api/v1/captures/sha256%3Aaa/download',
      );
    });
  });

  it('View action opens the capture metadata panel without a network call', async () => {
    const user = userEvent.setup();
    let networkCalls = 0;
    installFetch((url) => {
      networkCalls += 1;
      if (url.includes('/captures?'))
        return respond(200, { data: CAPTURES, meta: { total: 2, total_pages: 1 } });
      if (url.includes('/probes') || url.includes('/interfaces'))
        return respond(200, { data: [], meta: {} });
      if (url.includes('/auth/me'))
        return respond(200, {
          data: {
            authenticated: false,
            role: 'viewer',
            permissions: [],
            capture_control: false,
            capture_execution_enabled: false,
            reason: 'VIEWER',
          },
          meta: {},
        });
      return respond(200, { data: [], meta: {} });
    });
    render(renderWithProviders(<CaptureLibraryPage />));
    await waitFor(() =>
      expect(screen.getByText('historical-ng-c')).toBeInTheDocument(),
    );
    const before = networkCalls;
    await user.click(screen.getByTestId('view-sha256:aa'));
    expect(screen.getByTestId('capture-detail')).toBeInTheDocument();
    expect(networkCalls).toBe(before);
  });
});

describe('Capture Library — server-side pagination (PR #2 Section 4)', () => {
  it('requests page 1 at the configured page size on mount', async () => {
    const captured: string[] = [];
    installFetch((url) => {
      if (url.includes('/captures?')) {
        captured.push(url);
        return respond(200, {
          data: makePaginatedCaptures(10),
          meta: { total: 240, total_pages: 10, page: 1 },
        });
      }
      if (url.includes('/probes') || url.includes('/interfaces'))
        return respond(200, { data: [], meta: {} });
      if (url.includes('/auth/me'))
        return respond(200, { data: { authenticated: false }, meta: {} });
      return respond(200, { data: [], meta: {} });
    });
    render(renderWithProviders(<CaptureLibraryPage defaultPageSize={25} />));
    await waitFor(() => expect(captured.length).toBeGreaterThan(0));
    const parsed = parsePaginationFromUrl(captured[0]);
    expect(parsed.page).toBe(1);
    expect(parsed.pageSize).toBe(25);
  });

  it('loads the next page via the Next button and keeps filters', async () => {
    const captured: string[] = [];
    installFetch((url) => {
      if (url.includes('/captures?')) {
        captured.push(url);
        const { page } = parsePaginationFromUrl(url);
        const all = makePaginatedCaptures(205);
        const start = (page - 1) * 25;
        return respond(200, {
          data: all.slice(start, start + 25),
          meta: { total: 205, total_pages: 9, page },
        });
      }
      if (url.includes('/probes') || url.includes('/interfaces'))
        return respond(200, { data: [], meta: {} });
      if (url.includes('/auth/me'))
        return respond(200, { data: { authenticated: false }, meta: {} });
      return respond(200, { data: [], meta: {} });
    });
    const user = userEvent.setup();
    render(renderWithProviders(<CaptureLibraryPage defaultPageSize={25} />));
    await waitFor(() => expect(screen.getByTestId('capture-table')).toBeInTheDocument());
    await user.click(screen.getByTestId('pagination-next'));
    await waitFor(() => {
      const parsed = captured.map(parsePaginationFromUrl);
      expect(parsed.some((p) => p.page === 2)).toBe(true);
    });
    expect(screen.getByTestId('capture-pagination').textContent).toMatch(/of\s*9/);
  });

  it('shows the partial-results notice when the backend omits meta.total', async () => {
    installFetch((url) => {
      if (url.includes('/captures?')) {
        return respond(200, {
          data: makePaginatedCaptures(25),
          meta: {},
        });
      }
      if (url.includes('/probes') || url.includes('/interfaces'))
        return respond(200, { data: [], meta: {} });
      if (url.includes('/auth/me'))
        return respond(200, { data: { authenticated: false }, meta: {} });
      return respond(200, { data: [], meta: {} });
    });
    render(renderWithProviders(<CaptureLibraryPage defaultPageSize={25} />));
    await waitFor(() =>
      expect(screen.getByTestId('partial-results-notice')).toBeInTheDocument(),
    );
    expect(screen.getByTestId('capture-pagination').textContent).toMatch(
      /total unknown/i,
    );
  });

  it('disables Previous on the first page and Next on the last known page', async () => {
    installFetch((url) => {
      if (url.includes('/captures?')) {
        return respond(200, {
          data: makePaginatedCaptures(10),
          meta: { total: 10, total_pages: 1, page: 1 },
        });
      }
      if (url.includes('/probes') || url.includes('/interfaces'))
        return respond(200, { data: [], meta: {} });
      if (url.includes('/auth/me'))
        return respond(200, { data: { authenticated: false }, meta: {} });
      return respond(200, { data: [], meta: {} });
    });
    render(renderWithProviders(<CaptureLibraryPage defaultPageSize={25} />));
    await waitFor(() => expect(screen.getByTestId('capture-table')).toBeInTheDocument());
    expect(screen.getByTestId('pagination-previous')).toBeDisabled();
    expect(screen.getByTestId('pagination-next')).toBeDisabled();
  });
});
