import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { PacketAnalyzer } from '../pages/PacketAnalyzer';
import { api } from '../services/api';

vi.mock('../services/api', () => ({ api: vi.fn(), downloadExport: vi.fn() }));

// Packet payload shaped like the OIRAN response. The `information_elements`
// array is intentionally a mix of safe fields and the decoder-sourced
// identity strings that leaked in BC4; the Fields tab must drop every
// identity line and surface the "N withheld" banner.
const packet = {
  packet_id: 'pkt-1',
  capture_id: 'cap-certified',
  event_id: 'evt-1',
  timestamp: '1792872460.866283311Z',
  timestamp_ns: '1792872460866283311',
  interface: 'N2',
  protocol: 'NGAP',
  source: 'gNB',
  destination: 'AMF',
  direction: 'gNB_TO_AMF',
  message_name: 'InitialUEMessage',
  captured_length: 160,
  original_length: 160,
  byte_offset: 128,
  packet_number: 7,
  source_file: 'capture://N2.pcapng',
  decode_status: 'DECODED',
  decoder_name: 'decoder-ngap',
  decoder_version: '1.0.0',
  raw_payload_reference: 'sha256:payload',
  information_elements: [
    { id: 85, name: 'RAN UE NGAP ID', length: 4, value: '42', raw_sha256: null, status: 'DECODED' },
    // 2.4.1 BC4 cases: these must be withheld.
    { id: 200, name: '5GS mobile identity', length: 9, value: 'imsi-208990000000001', raw_sha256: null, status: 'DECODED' },
    { id: 201, name: 'FiveG-S-TMSI', length: 7, value: 'guti-raw', raw_sha256: null, status: 'DECODED' },
    { id: 202, name: 'MaskedIMEISV', length: 8, value: 'imeisv-raw', raw_sha256: null, status: 'DECODED' },
    { id: 203, name: 'ue_identity_pseudonym', length: 16, value: 'psn-abc123', raw_sha256: null, status: 'DECODED' },
  ],
};

const payload = { data: [packet], meta: { page: 1, total_pages: 1, total: 1 } };

beforeEach(() =>
  vi.mocked(api).mockImplementation(async (path?: string) => {
    if (path === undefined) return { data: [], meta: {} } as never;
    if (path.startsWith('/packets')) return payload as never;
    throw new Error(`unexpected path ${path}`);
  }),
);

function renderPage(route = '/analysis/packets') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[route]}>
        <PacketAnalyzer />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('PacketAnalyzer — Fields tab (2.4.1, BC4)', () => {
  it('surfaces the "N identity IEs withheld" banner on the Fields tab', async () => {
    renderPage();
    await userEvent.click(await screen.findByRole('tab', { name: /Fields/ }));
    const banners = screen.getAllByTestId('packet-identity-withheld-banner');
    expect(banners.length).toBeGreaterThan(0);
    expect(banners[0].textContent).toMatch(/3 identity IEs withheld/);
  });

  it('removes 5GS mobile identity / FiveG-S-TMSI / MaskedIMEISV from the DOM', async () => {
    renderPage();
    await userEvent.click(await screen.findByRole('tab', { name: /Fields/ }));
    expect(screen.queryByText('5GS mobile identity')).toBeNull();
    expect(screen.queryByText('FiveG-S-TMSI')).toBeNull();
    expect(screen.queryByText('MaskedIMEISV')).toBeNull();
  });

  it('keeps RAN UE NGAP ID and ue_identity_pseudonym — these are not subscriber identities', async () => {
    renderPage();
    await userEvent.click(await screen.findByRole('tab', { name: /Fields/ }));
    expect(screen.getAllByText('RAN UE NGAP ID')[0]).toBeVisible();
    expect(screen.getAllByText('ue_identity_pseudonym')[0]).toBeVisible();
  });

  it('restates the identity-IE lock on the Raw Hex tab (no bytes ever)', async () => {
    renderPage();
    await userEvent.click(await screen.findByRole('tab', { name: 'Raw Hex' }));
    expect(screen.getByText('Raw bytes not available')).toBeVisible();
    expect(screen.getByText(/Identity IEs are withheld; this packet is shown without hex/)).toBeVisible();
  });
});
