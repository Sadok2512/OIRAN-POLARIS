// 0.13.0 — Traffic Generator (#47) front, driven by polaris-control-api
// 0.20.0 `/traffic/sessions`.
// 0.13.1 — Live sparkline per running session: polls the new
// polaris-api 0.20.1 `/traffic/sessions/:id/samples` endpoint at 1 Hz
// and draws UL + DL rate traces as an SVG polyline. No new npm dep.
// The polling stops as soon as the session leaves RUNNING, so a
// finished session does not keep spamming the API.
//
// Rules surfaced to the operator:
//   - rate_mbps slider pinned to [1, 50]; the help line shows "UDP sans
//     perte ≤ 20 Mbit/s" (lab ceiling).
//   - duration_s slider pinned to [1, 600].
//   - direction ∈ UL | DL | BOTH; protocol ∈ TCP | UDP.
//   - Start requires an operator session + a covered grant (same as
//     scenario Run); the backend returns 403 / 423 if the grant is
//     missing — the UI surfaces the exact code.
//   - Stop is always allowed; even a viewer can stop a running session.
//   - iperf3 is measurement, never blocking: warnings in the IPERF3_*
//     vocabulary appear as yellow chips, never red failures.

import { useState } from 'react';
import { Activity, Download, StopCircle, Upload, Zap } from 'lucide-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Btn, Card, PageHeader, Pill } from '@/components/mockup';
import { ErrorState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import { useAuth } from '@/data/queries';
import {
  TRAFFIC_DURATION_S_MAX,
  TRAFFIC_DURATION_S_MIN,
  TRAFFIC_RATE_MBPS_MAX,
  TRAFFIC_RATE_MBPS_MIN,
  UDP_LOSSLESS_CEILING_MBPS,
  fetchTrafficSamples,
  fetchTrafficSessions,
  startTrafficSession,
  stopTrafficSession,
  validateTrafficRequest,
  type TrafficDirection,
  type TrafficProtocol,
  type TrafficSession,
  type TrafficSessionRequest,
} from '@/data/trafficSessionsApi';
import { TrafficSparkline } from '@/components/TrafficSparkline';
import { ApiError } from '@shared/api';
import { TechnologySelector, type RadioTechnology } from '@/components/TechnologySelector';
import { useLteStatus } from '@/data/queries';

const QUERY_KEY = ['polaris', 'traffic-sessions'] as const;

function formatRate(bps: number | null): string {
  if (bps == null) return '—';
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(2)} Mbit/s`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} kbit/s`;
  return `${bps} bit/s`;
}

function stateTone(state: TrafficSession['state']) {
  switch (state) {
    case 'RUNNING':
      return 'ok' as const;
    case 'REQUESTED':
      return 'brand' as const;
    case 'COMPLETED':
      return 'ok' as const;
    case 'STOPPED':
      return 'mute' as const;
    case 'FAILED':
      return 'bad' as const;
    default:
      return 'mute' as const;
  }
}

function TrafficSparklineRow({ session }: { session: TrafficSession }) {
  // 0.13.1 — poll /samples at 1 s while the session is RUNNING. On any
  // terminal state we leave the last-fetched ring on screen so the
  // operator keeps the final shape of the run.
  const isLive = session.state === 'RUNNING' || session.state === 'REQUESTED';
  const samples = useQuery({
    queryKey: ['polaris', 'traffic-samples', session.session_id],
    queryFn: () => fetchTrafficSamples(session.session_id).then((r) => r.items),
    refetchInterval: isLive ? 1_000 : false,
    enabled: true,
  });
  return (
    <div
      className="flex items-center gap-3"
      data-testid={`traffic-sparkline-row-${session.session_id}`}
    >
      <TrafficSparkline
        samples={samples.data ?? []}
        label={session.session_id}
      />
      <div className="text-xs2 text-mute flex flex-col gap-0.5">
        <span>
          <span className="inline-block w-2 h-2 rounded-full bg-ok mr-1" />
          UL
        </span>
        <span>
          <span className="inline-block w-2 h-2 rounded-full bg-brand mr-1" />
          DL
        </span>
      </div>
    </div>
  );
}

export function TrafficSessionsPage() {
  const auth = useAuth();
  const canOperate = auth.data?.can_start === true;
  const client = useQueryClient();
  const lte = useLteStatus();
  const lteTrafficAllowed = lte.data?.traffic_allowed === true;

  const [ueIds, setUeIds] = useState('UE-01');
  const [technology, setTechnology] = useState<RadioTechnology>('5G_SA');
  const [direction, setDirection] = useState<TrafficDirection>('BOTH');
  const [protocol, setProtocol] = useState<TrafficProtocol>('UDP');
  const [rateMbps, setRateMbps] = useState(5);
  const [durationS, setDurationS] = useState(30);
  const [formError, setFormError] = useState<string | null>(null);

  const list = useQuery({
    queryKey: QUERY_KEY,
    queryFn: () => fetchTrafficSessions().then((x) => x.items),
    refetchInterval: 2_000,
  });

  const start = useMutation({
    mutationFn: (body: TrafficSessionRequest) => startTrafficSession(body),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: QUERY_KEY });
    },
  });

  const stop = useMutation({
    mutationFn: (id: string) => stopTrafficSession(id),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: QUERY_KEY });
    },
  });

  function submit() {
    setFormError(null);
    const body: TrafficSessionRequest = {
      ue_ids: ueIds
        .split(/[\s,]+/)
        .map((x) => x.trim())
        .filter(Boolean),
      direction,
      protocol,
      rate_mbps: rateMbps,
      duration_s: durationS,
    };
    const err = validateTrafficRequest(body);
    if (err) {
      setFormError(err);
      return;
    }
    start.mutate(body, {
      onError: (error) => {
        if (error instanceof ApiError) {
          setFormError(`HTTP ${error.status} · ${error.code}`);
        } else {
          setFormError((error as Error).message);
        }
      },
    });
  }

  return (
    <>
      <PageHeader
        eyebrow="Simulation"
        title="Traffic Generator"
        desc="Ponctual iperf3-measured UL / DL sessions per UE. Lab ceiling: 50 Mbit/s hard; UDP lossless ≤ 20 Mbit/s. Stops never require a grant."
      />

      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <TechnologySelector
          value={technology}
          onChange={(next) => {
            setTechnology(next);
            setUeIds(next === 'LTE' ? 'LTE-SRSUE-TEST-01' : 'UE-01');
            if (next === 'LTE') {
              setProtocol('UDP');
              setRateMbps(1);
              setDurationS(30);
            }
          }}
        />
        {technology === 'LTE' ? (
          <span className="text-ep-sm text-warn">
            LTE traffic: {lteTrafficAllowed ? 'READY' : 'LOCKED'}; attach: {lte.data?.attach_state ?? 'UNKNOWN'}; ownership: {lte.data?.ownership_verified ? 'VERIFIED' : 'UNVERIFIED'}.
          </span>
        ) : null}
      </div>

      <Card className="p-5 flex flex-col gap-4" data-testid="traffic-form">
        <div className="grid gap-3 md:grid-cols-2">
          <label className="flex flex-col gap-1 text-sm2">
            <span className="text-xs2 uppercase tracking-wider text-mute">
              UE ids (comma or space separated)
            </span>
            <input
              className="h-9 px-3 rounded-md border border-line bg-surface text-md2 text-ink mono"
              placeholder="UE-01, UE-02"
              value={ueIds}
              onChange={(e) => setUeIds(e.target.value)}
              data-testid="traffic-ue-ids"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm2">
            <span className="text-xs2 uppercase tracking-wider text-mute">Direction</span>
            <select
              className="h-9 px-3 rounded-md border border-line bg-surface text-md2 text-ink"
              value={direction}
              onChange={(e) => setDirection(e.target.value as TrafficDirection)}
              data-testid="traffic-direction"
            >
              <option value="UL">Uplink only</option>
              <option value="DL">Downlink only</option>
              <option value="BOTH">UL + DL (bidirectional)</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-sm2">
            <span className="text-xs2 uppercase tracking-wider text-mute">Protocol</span>
            <select
              className="h-9 px-3 rounded-md border border-line bg-surface text-md2 text-ink"
              value={protocol}
              onChange={(e) => setProtocol(e.target.value as TrafficProtocol)}
              data-testid="traffic-protocol"
            >
              <option value="UDP">UDP</option>
              <option value="TCP" disabled={technology === 'LTE'}>TCP</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-sm2">
            <span className="text-xs2 uppercase tracking-wider text-mute">
              Rate {rateMbps} Mbit/s{' '}
              <span className="text-mute">
                · lab UDP lossless ≤ {UDP_LOSSLESS_CEILING_MBPS} Mbit/s
              </span>
            </span>
            <input
              type="range"
              min={TRAFFIC_RATE_MBPS_MIN}
              max={technology === 'LTE' ? 1 : TRAFFIC_RATE_MBPS_MAX}
              value={rateMbps}
              onChange={(e) => setRateMbps(Number(e.target.value))}
              data-testid="traffic-rate"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm2">
            <span className="text-xs2 uppercase tracking-wider text-mute">
              Duration {durationS} s
            </span>
            <input
              type="range"
              min={TRAFFIC_DURATION_S_MIN}
              max={technology === 'LTE' ? 30 : TRAFFIC_DURATION_S_MAX}
              value={durationS}
              onChange={(e) => setDurationS(Number(e.target.value))}
              data-testid="traffic-duration"
            />
          </label>
        </div>
        <div className="flex items-center gap-3 border-t border-line pt-3">
          <Btn
            icon={Zap}
            primary
            onClick={submit}
            disabled={!canOperate || start.isPending || (technology === 'LTE' && !lteTrafficAllowed)}
            title={technology === 'LTE' && !lteTrafficAllowed ? 'LTE requires certification, valid grant, verified controller ownership, current attach/IP/session and safety gates.' : canOperate ? undefined : 'Rôle operator requis + grant actif.'}
            data-testid="traffic-start"
          >
            {start.isPending ? 'Starting…' : technology === 'LTE' && !lteTrafficAllowed ? 'LTE traffic locked' : 'Start session'}
          </Btn>
          {formError ? (
            <span className="text-sm2 text-bad" data-testid="traffic-form-error">
              {formError}
            </span>
          ) : null}
        </div>
      </Card>

      <h2 className="text-xl2 font-semibold mt-4">Live sessions</h2>
      {list.isLoading && !list.data ? (
        <LoadingSkeleton label="Loading /traffic/sessions" />
      ) : list.error ? (
        <ErrorState
          title="Could not load /traffic/sessions"
          detail={(list.error as Error).message}
          onRetry={() => void list.refetch()}
        />
      ) : (list.data ?? []).length === 0 ? (
        <Card className="p-5">
          <p className="text-sm2 text-mute">No traffic session yet.</p>
        </Card>
      ) : (
        <div className="flex flex-col gap-3">
          {(list.data ?? []).map((session) => (
            <Card
              key={session.session_id}
              className="p-5"
              data-testid={`traffic-session-${session.session_id}`}
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold">
                      {session.request.ue_ids.join(', ')}
                    </h3>
                    <Pill tone={stateTone(session.state)}>{session.state}</Pill>
                  </div>
                  <p className="mono text-xs2 text-mute truncate" title={session.session_id}>
                    {session.session_id}
                  </p>
                  <p className="text-sm2 text-mute mt-1">
                    {session.request.direction} · {session.request.protocol} ·{' '}
                    {session.request.rate_mbps} Mbit/s · {session.request.duration_s}s
                  </p>
                </div>
                <Btn
                  icon={StopCircle}
                  danger
                  onClick={() => stop.mutate(session.session_id)}
                  disabled={
                    stop.isPending ||
                    session.state === 'STOPPED' ||
                    session.state === 'COMPLETED'
                  }
                  data-testid={`traffic-stop-${session.session_id}`}
                >
                  Stop
                </Btn>
              </div>
              {session.warnings.length > 0 ? (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {session.warnings.map((w) => (
                    <Pill key={w} tone="warn">
                      {w}
                    </Pill>
                  ))}
                </div>
              ) : null}
              <div className="mt-3 border-t border-line pt-3">
                <TrafficSparklineRow session={session} />
              </div>
              <div className="mt-3 border-t border-line pt-3 overflow-x-auto">
                <table className="w-full text-sm2">
                  <thead>
                    <tr className="text-left text-xs2 uppercase tracking-wider text-mute">
                      <th className="py-1.5 pr-3">UE</th>
                      <th className="py-1.5 pr-3">
                        <Upload width={11} height={11} className="inline" /> UL rate
                      </th>
                      <th className="py-1.5 pr-3">
                        <Download width={11} height={11} className="inline" /> DL rate
                      </th>
                      <th className="py-1.5 pr-3">UL bytes</th>
                      <th className="py-1.5 pr-3">DL bytes</th>
                      <th className="py-1.5 pr-3">Warnings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {session.ue_counters.map((ue) => (
                      <tr key={ue.ue_id} className="border-t border-line">
                        <td className="py-1.5 pr-3 mono">{ue.ue_id}</td>
                        <td className="py-1.5 pr-3 mono">{formatRate(ue.rate_ul_bps)}</td>
                        <td className="py-1.5 pr-3 mono">{formatRate(ue.rate_dl_bps)}</td>
                        <td className="py-1.5 pr-3 mono">
                          {ue.bytes_ul.toLocaleString('en-US')}
                        </td>
                        <td className="py-1.5 pr-3 mono">
                          {ue.bytes_dl.toLocaleString('en-US')}
                        </td>
                        <td className="py-1.5 pr-3 text-xs2">
                          {ue.warnings.length === 0 ? (
                            <span className="text-mute">—</span>
                          ) : (
                            ue.warnings.join(' · ')
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          ))}
        </div>
      )}

      <p className="text-xs2 text-mute mt-2 flex items-center gap-1">
        <Activity width={11} height={11} />
        iperf3 is a measurement; warnings never fail a session (polaris-api 0.19.8).
      </p>
    </>
  );
}
