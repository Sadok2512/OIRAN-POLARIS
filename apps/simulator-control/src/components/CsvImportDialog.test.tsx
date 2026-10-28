// 0.6.0 — Shared CSV import dialog. We cover:
//   * Preview surfaces row count and allows upload when under cap.
//   * Over-cap files (100 001+) refuse to upload locally — no POST hits
//     the backend.
//   * Backend 422 reports render as a per-line table (code column +
//     message).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { CsvImportDialog } from './CsvImportDialog';

function makeCsv(lines: number): File {
  const header = 'imsi,k,opc,sst,sd,dnns,ambr_uplink,ambr_downlink';
  const row = '208930000000000,00112233445566778899aabbccddeeff,ffeeddccbbaa99887766554433221100,1,010203,internet,1000000,2000000';
  const text = `${header}\n${Array.from({ length: lines - 1 }, () => row).join('\n')}`;
  const file = new File([text], 'subs.csv', { type: 'text/csv' });
  Object.defineProperty(file, 'text', { value: async () => text });
  return file;
}

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const calls: { method: string; url: string; headers: Headers; body: string }[] = [];

beforeEach(() => {
  calls.length = 0;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === 'string' ? init.body : '';
    calls.push({ method, url, headers, body });
    // 0.6.1 — real contract: POST /subscribers/bulk (text/csv body).
    if (url.endsWith('/subscribers/bulk')) {
      return respond(200, {
        ok: 8,
        errors: 2,
        results: [
          { row: 3, ok: false, error: 'SUBSCRIBER_NOT_POLARIS_OWNED' },
          { row: 7, ok: false, error: 'SUBSCRIBER_NOT_PROVISIONED' },
        ],
      });
    }
    return respond(404, { error: 'not stubbed' });
  }) as unknown as typeof fetch;
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('CsvImportDialog', () => {
  it('previews a small file and renders the backend per-line error report after upload', async () => {
    const user = userEvent.setup();
    render(
      <CsvImportDialog
        open
        onClose={() => undefined}
        target="subscribers"
        title="Import subscribers (CSV)"
        description="dummy"
      />,
    );

    await user.upload(screen.getByTestId('csv-file-field') as HTMLInputElement, makeCsv(10));
    await screen.findByTestId('csv-preview');
    expect(screen.getByTestId('csv-preview')).toHaveTextContent('10 lines');
    expect(screen.getByTestId('csv-ok-under-cap')).toBeInTheDocument();

    await user.click(screen.getByTestId('csv-upload-submit'));
    await screen.findByTestId('csv-import-report');
    expect(screen.getByTestId('csv-import-report')).toHaveTextContent('8 accepted');
    expect(screen.getByTestId('csv-import-error-3')).toHaveTextContent('SUBSCRIBER_NOT_POLARIS_OWNED');
    expect(screen.getByTestId('csv-import-error-7')).toHaveTextContent('SUBSCRIBER_NOT_PROVISIONED');

    // 0.6.1 — the real contract uses text/csv (raw body), not multipart.
    const uploadCall = calls.find(
      (c) => c.method === 'POST' && c.url.endsWith('/subscribers/bulk'),
    );
    expect(uploadCall).toBeDefined();
    expect(uploadCall?.headers.get('content-type')).toBe('text/csv');
    expect(uploadCall?.body).toContain('imsi,k,opc,sst,sd,dnns,ambr_uplink,ambr_downlink');
  });

  it('refuses to upload a file over the 100 000-row cap and never POSTs', async () => {
    const user = userEvent.setup();
    render(
      <CsvImportDialog
        open
        onClose={() => undefined}
        target="subscribers"
        title="Import subscribers (CSV)"
        description="dummy"
      />,
    );

    // Build a 100 001-row file (small enough string in memory in tests).
    await user.upload(
      screen.getByTestId('csv-file-field') as HTMLInputElement,
      makeCsv(100_001),
    );
    // Parsing 100,001 rows is deliberately chunked/yielding and can exceed the
    // DOM query default on a loaded build host. Keep the assertion unchanged,
    // but allow the bounded parser to finish.
    await screen.findByTestId('csv-too-big', {}, { timeout: 30_000 });
    expect(screen.getByTestId('csv-upload-submit')).toBeDisabled();

    // Clicking the (disabled) submit button must not POST.
    await user.click(screen.getByTestId('csv-upload-submit')).catch(() => undefined);
    await waitFor(() => expect(calls.find((c) => c.method === 'POST')).toBeUndefined());
  });
});
