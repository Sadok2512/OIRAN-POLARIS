// LOT C8 (ordres cœur #9 7222823828 et 7223299148) — le formulaire 5G de
// sessions de trafic ne propose plus un protocole que le serveur refuse.
//
// Depuis C2b (polaris-control-api 0.37.0), `POST /traffic/sessions` refuse
// une session 5G en UDP (HTTP 422 `TRAFFIC_5G_UDP_NOT_MEASURED`) : le chemin
// 5G ne mesure qu'en TCP. Le formulaire s'initialisait pourtant en UDP, donc
// toute session 5G lancée depuis l'interface échouait sans que l'opérateur
// ait rien choisi de faux. Ces gardes testent la clé, pas la serrure : ce
// que le formulaire ENVOIE, pas ce que le serveur refuse.

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('@/data/queries', () => ({
  useAuth: () => ({ data: { authenticated: true, can_start: true } }),
  useLteStatus: () => ({
    data: { traffic_allowed: true, attach_state: 'ATTACHED', ownership_verified: true },
  }),
  useLteProfile: () => ({ data: { profile_id: 'LTE-SRSUE-TEST-01' } }),
  useUes: () => ({
    data: { items: [{ id: 'UE-05', internal_ue_id: 'UE-05', technology: '5G SA', simulator: 'UERANSIM' }] },
  }),
}));

const startTrafficSession = vi.fn();

vi.mock('@/data/trafficSessionsApi', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/data/trafficSessionsApi')>();
  return {
    ...actual,
    fetchTrafficSessions: vi.fn(async () => ({ items: [], total: 0 })),
    fetchTrafficSamples: vi.fn(async () => ({ items: [] })),
    startTrafficSession: (body: unknown) => {
      startTrafficSession(body);
      return Promise.resolve({ session_id: 'traffic-test' });
    },
    stopTrafficSession: vi.fn(async () => ({})),
  };
});

import { TrafficSessionsPage } from './TrafficSessions';

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TrafficSessionsPage />
    </QueryClientProvider>,
  );
}

function protocolSelect() {
  return screen.getByTestId('traffic-protocol') as HTMLSelectElement;
}

function udpOption() {
  return Array.from(protocolSelect().options).find((option) => option.value === 'UDP')!;
}

async function startAndReadProtocol(): Promise<string | undefined> {
  await waitFor(() => expect((screen.getByTestId('traffic-ue-ids') as HTMLSelectElement).value).not.toBe(''));
  fireEvent.click(screen.getByTestId('traffic-start'));
  await waitFor(() => expect(startTrafficSession).toHaveBeenCalled());
  return (startTrafficSession.mock.calls.at(-1)?.[0] as { protocol?: string })?.protocol;
}

beforeEach(() => {
  startTrafficSession.mockClear();
});

describe('TrafficSessions — formulaire 5G (lot C8)', () => {
  it('initialise le protocole du formulaire 5G en TCP, le seul mesuré', () => {
    renderPage();
    expect(screen.getByTestId('technology-5g').getAttribute('aria-pressed')).toBe('true');
    expect(protocolSelect().value).toBe('TCP');
  });

  it("propose l'UDP désactivé sur le 5G, avec son motif affiché", () => {
    renderPage();
    expect(udpOption().disabled).toBe(true);
    expect(screen.getByTestId('traffic-protocol-5g-udp-reason').textContent).toContain(
      'TRAFFIC_5G_UDP_NOT_MEASURED',
    );
  });

  it("n'émet jamais protocol UDP depuis le formulaire 5G, même si la valeur est forcée", async () => {
    renderPage();
    fireEvent.change(protocolSelect(), { target: { value: 'UDP' } });
    const sent = await startAndReadProtocol();
    expect(sent).toBe('TCP');
    for (const [body] of startTrafficSession.mock.calls) {
      expect((body as { protocol: string }).protocol).not.toBe('UDP');
    }
  });

  it('repasse en TCP en revenant du LTE vers le 5G', async () => {
    renderPage();
    fireEvent.click(screen.getByTestId('technology-lte'));
    expect(protocolSelect().value).toBe('UDP');
    fireEvent.click(screen.getByTestId('technology-5g'));
    expect(protocolSelect().value).toBe('TCP');
    expect(await startAndReadProtocol()).toBe('TCP');
  });

  it("laisse le chemin LTE tel quel : UDP réel, TCP désactivé", async () => {
    renderPage();
    fireEvent.click(screen.getByTestId('technology-lte'));
    expect(protocolSelect().value).toBe('UDP');
    expect(udpOption().disabled).toBe(false);
    const tcp = Array.from(protocolSelect().options).find((option) => option.value === 'TCP')!;
    expect(tcp.disabled).toBe(true);
    expect(screen.queryByTestId('traffic-protocol-5g-udp-reason')).toBeNull();
    expect(await startAndReadProtocol()).toBe('UDP');
  });
});
