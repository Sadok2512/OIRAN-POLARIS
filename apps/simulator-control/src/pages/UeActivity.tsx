// 0.11.0 (#37) — Per-UE Activity page.
//
// Opened from:
//   * UE Manager row (click on the UE ID column) — new destination
//     for the existing /ues/:ueId link.
//   * Topology UE mini-card (wraps the card in a react-router Link).
//
// What it shows:
//   * 4 state chips (RM / CM / RRC / 5GMM).
//   * UL / DL cumulative bytes + live bps (sparkline over 2 min).
//   * Current job + step pulled from `job_step` on the payload.
//   * Timeline of the last 20 events emitted by the backend ring.
//   * Voice panel pinned to "IMS not available" (no stub call button).
//
// Data flow:
//   * First render → one-shot `GET /ues/:id/activity` for an immediate
//     paint even when the browser blocks EventSource.
//   * Then an EventSource subscription to
//     `GET /ues/:id/activity/stream` receiving the same payload every
//     2 s. On close / error the live indicator flips to "Reconnexion…"
//     and the page falls back to a 5 s polling loop.

import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  Activity,
  ArrowLeft,
  CircleDashed,
  Mic,
  Radio,
  Signal,
  Wifi,
} from 'lucide-react';
import { PageHeader } from '@/components/mockup';
import { StatusIndicator } from '@/ui/StatusIndicator';

interface ActivityStates {
  rm_state?: string | null;
  cm_state?: string | null;
  rrc_state?: string | null;
  mm_5g_state?: string | null;
}

interface ActivityPdu {
  psi?: number | null;
  dnn?: string | null;
  state?: string | null;
  address?: string | null;
}

interface ActivityCounters {
  interface?: string | null;
  rx_bytes: number;
  rx_packets: number;
  tx_bytes: number;
  tx_packets: number;
  rx_bps?: number | null;
  tx_bps?: number | null;
}

interface ActivityJobStep {
  job_id?: string | null;
  definition_id?: string | null;
  state?: string | null;
  current_step?: { index: number; type: string; state: string } | null;
}

interface ActivityEvent {
  epoch_s: number;
  kind: string;
  outcome: string;
  detail: Record<string, unknown>;
}

export interface UeActivityPayload {
  ue_id: string;
  running: boolean;
  reason?: string | null;
  imsi?: string | null;
  states?: ActivityStates;
  pdu?: ActivityPdu | null;
  counters?: ActivityCounters | null;
  job_step?: ActivityJobStep | null;
  events?: ActivityEvent[];
  voice?: { available: boolean; reason: string };
}

const MAX_SAMPLES = 60; // 2 min at 2 s cadence.
const POLL_FALLBACK_MS = 5_000;

interface Sample {
  epoch_s: number;
  rx_bps: number;
  tx_bps: number;
}

export function UeActivityPage() {
  const { ueId: rawUeId } = useParams<{ ueId: string }>();
  const ueId = rawUeId ?? '';
  const [payload, setPayload] = useState<UeActivityPayload | null>(null);
  const [liveStatus, setLiveStatus] = useState<'connecting' | 'live' | 'reconnecting'>(
    'connecting',
  );
  const [samples, setSamples] = useState<Sample[]>([]);

  const payloadRef = useRef<UeActivityPayload | null>(null);
  useEffect(() => {
    payloadRef.current = payload;
  }, [payload]);

  // First paint: one-shot fetch so the page never shows a blank state
  // while the SSE handshake is in flight.
  useEffect(() => {
    if (!ueId) return;
    let cancelled = false;
    void fetchSnapshot(ueId).then((data) => {
      if (!cancelled && data) {
        setPayload(data);
        appendSample(setSamples, data);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [ueId]);

  // Live stream: EventSource to the SSE endpoint. On open → `live`. On
  // error → `reconnecting`; browsers retry automatically every ~3 s.
  // If the stream is unusable we also schedule a plain polling tick
  // every 5 s so the page stays current.
  useEffect(() => {
    if (!ueId) return;
    const url = `/polaris-api/v1/ues/${encodeURIComponent(ueId)}/activity/stream`;
    const source = new EventSource(url, { withCredentials: true });
    setLiveStatus('connecting');
    source.onopen = () => setLiveStatus('live');
    source.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as UeActivityPayload;
        setPayload(data);
        appendSample(setSamples, data);
      } catch {
        // ignore malformed frames
      }
    };
    source.onerror = () => setLiveStatus('reconnecting');
    const fallback = window.setInterval(() => {
      if (source.readyState === EventSource.OPEN) return;
      void fetchSnapshot(ueId).then((data) => {
        if (data) {
          setPayload(data);
          appendSample(setSamples, data);
        }
      });
    }, POLL_FALLBACK_MS);
    return () => {
      source.close();
      window.clearInterval(fallback);
    };
  }, [ueId]);

  const chips = useMemo(() => buildStateChips(payload?.states ?? {}, payload?.running), [
    payload?.states,
    payload?.running,
  ]);

  return (
    <>
      <PageHeader
        eyebrow="Observation"
        title={`UE ${ueId} — Activity`}
        description="État temps réel du UE : RM/CM/RRC/5GMM, PDU, débits UL/DL, job en cours, timeline des événements."
        actions={
          <div className="flex items-center gap-2">
            <Link
              to={`/ues/${encodeURIComponent(ueId)}`}
              className="ep-button ep-button-sm"
              data-testid="activity-back-detail"
            >
              <ArrowLeft width={13} height={13} aria-hidden="true" />
              UE detail
            </Link>
            <LiveIndicator status={liveStatus} />
          </div>
        }
      />

      {!payload ? (
        <div
          className="ep-card p-4 text-ep-sm text-text-secondary"
          data-testid="activity-loading"
        >
          Loading UE activity…
        </div>
      ) : !payload.running ? (
        <section
          className="ep-card border-warning/40 bg-warning/5 p-4 flex items-start gap-2"
          data-testid="activity-not-running"
        >
          <CircleDashed width={14} height={14} className="shrink-0 text-warning mt-0.5" aria-hidden="true" />
          <div className="flex flex-col gap-1">
            <p className="text-ep-sm font-medium">UE non démarré.</p>
            <p className="text-ep-xs text-text-secondary">
              Raison : <span className="mono">{payload.reason ?? 'UE_NOT_RUNNING'}</span>.
              Démarre l'UE depuis l'onglet UE Manager pour voir l'activité en direct.
            </p>
          </div>
        </section>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
          <section
            className="ep-card p-4 flex flex-col gap-3"
            data-testid="activity-states"
          >
            <h2 className="text-ep-sm font-semibold">États réseau</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {chips.map((chip) => (
                <ChipCard key={chip.label} chip={chip} />
              ))}
            </div>
            <IdentityRow imsi={payload.imsi} />
          </section>

          <section
            className="ep-card p-4 flex flex-col gap-2"
            data-testid="activity-pdu"
          >
            <h2 className="text-ep-sm font-semibold">PDU</h2>
            <PduBlock pdu={payload.pdu ?? null} />
          </section>

          <section
            className="ep-card p-4 flex flex-col gap-3 lg:col-span-2"
            data-testid="activity-throughput"
          >
            <h2 className="text-ep-sm font-semibold">Débit UL / DL</h2>
            <ThroughputBlock
              counters={payload.counters ?? null}
              samples={samples}
            />
          </section>

          <section
            className="ep-card p-4 flex flex-col gap-2"
            data-testid="activity-job"
          >
            <h2 className="text-ep-sm font-semibold">Job en cours</h2>
            <JobBlock jobStep={payload.job_step ?? null} />
          </section>

          <section
            className="ep-card p-4 flex flex-col gap-2"
            data-testid="activity-voice"
          >
            <h2 className="text-ep-sm font-semibold flex items-center gap-2">
              <Mic width={13} height={13} aria-hidden="true" /> Voix
            </h2>
            <p className="text-ep-sm text-text-secondary">
              IMS not available.
            </p>
            <p className="text-ep-xs text-text-secondary">
              <span className="mono">{payload.voice?.reason ?? 'IMS_NOT_AVAILABLE'}</span> —
              la pile IMS n'est pas déployée côté lab ; les appels ne peuvent pas être lancés.
            </p>
          </section>

          <section
            className="ep-card p-4 flex flex-col gap-2 lg:col-span-2"
            data-testid="activity-timeline"
          >
            <h2 className="text-ep-sm font-semibold">Événements récents (20 derniers)</h2>
            <TimelineBlock events={payload.events ?? []} />
          </section>
        </div>
      )}
    </>
  );
}

async function fetchSnapshot(ueId: string): Promise<UeActivityPayload | null> {
  try {
    const response = await fetch(
      `/polaris-api/v1/ues/${encodeURIComponent(ueId)}/activity`,
      { credentials: 'same-origin' },
    );
    if (!response.ok) return null;
    return (await response.json()) as UeActivityPayload;
  } catch {
    return null;
  }
}

function appendSample(
  setSamples: React.Dispatch<React.SetStateAction<Sample[]>>,
  payload: UeActivityPayload,
) {
  const counters = payload.counters;
  if (!counters) return;
  const now = Math.floor(Date.now() / 1_000);
  const next: Sample = {
    epoch_s: now,
    rx_bps: counters.rx_bps ?? 0,
    tx_bps: counters.tx_bps ?? 0,
  };
  setSamples((prev) => {
    const merged = [...prev, next];
    return merged.length > MAX_SAMPLES ? merged.slice(merged.length - MAX_SAMPLES) : merged;
  });
}

interface Chip {
  label: string;
  value: string;
  tone: 'success' | 'warning' | 'danger' | 'neutral' | 'info';
  icon: React.ReactNode;
}

function buildStateChips(states: ActivityStates, running: boolean | undefined): Chip[] {
  const r = (states.rm_state ?? '').toUpperCase();
  const c = (states.cm_state ?? '').toUpperCase();
  const rrc = (states.rrc_state ?? '').toUpperCase();
  const mm = (states.mm_5g_state ?? '').toUpperCase();
  return [
    {
      label: 'RM',
      value: states.rm_state ?? (running ? 'UNKNOWN' : 'Not running'),
      tone: r === 'RM-REGISTERED' || r === 'REGISTERED' ? 'success' : r.includes('DEREGISTERED') ? 'warning' : 'neutral',
      icon: <Radio width={13} height={13} aria-hidden="true" />,
    },
    {
      label: 'CM',
      value: states.cm_state ?? (running ? 'UNKNOWN' : 'Not running'),
      tone: c.includes('CONNECTED') ? 'success' : 'neutral',
      icon: <Signal width={13} height={13} aria-hidden="true" />,
    },
    {
      label: 'RRC',
      value: states.rrc_state ?? (running ? 'UNKNOWN' : 'Not running'),
      tone: rrc.includes('CONNECTED') ? 'success' : rrc.includes('IDLE') ? 'info' : 'neutral',
      icon: <Wifi width={13} height={13} aria-hidden="true" />,
    },
    {
      label: '5GMM',
      value: states.mm_5g_state ?? (running ? 'UNKNOWN' : 'Not running'),
      tone: mm.includes('REGISTERED-NORMAL-SERVICE') ? 'success' : mm.includes('REGISTERED') ? 'info' : 'neutral',
      icon: <Activity width={13} height={13} aria-hidden="true" />,
    },
  ];
}

function ChipCard({ chip }: { chip: Chip }) {
  return (
    <div
      className="rounded-lg border border-border bg-canvas p-3 flex flex-col gap-1"
      data-testid={`chip-${chip.label.toLowerCase()}`}
    >
      <span className="text-ep-xs uppercase tracking-wider text-text-secondary flex items-center gap-1">
        {chip.icon} {chip.label}
      </span>
      <StatusIndicator state={chip.value} tone={chip.tone} compact />
    </div>
  );
}

function IdentityRow({ imsi }: { imsi?: string | null }) {
  return (
    <p className="text-ep-xs text-text-secondary flex items-center gap-2">
      <span className="uppercase tracking-wider">IMSI</span>
      <span className="mono" data-testid="activity-imsi">
        {imsi ?? '—'}
      </span>
    </p>
  );
}

function PduBlock({ pdu }: { pdu: ActivityPdu | null }) {
  if (!pdu) {
    return <p className="text-ep-sm text-text-secondary">Aucune session PDU active.</p>;
  }
  return (
    <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-ep-sm">
      <dt className="text-text-secondary">PSI</dt>
      <dd className="mono" data-testid="activity-pdu-psi">
        {pdu.psi ?? '—'}
      </dd>
      <dt className="text-text-secondary">DNN</dt>
      <dd className="mono" data-testid="activity-pdu-dnn">
        {pdu.dnn ?? '—'}
      </dd>
      <dt className="text-text-secondary">État</dt>
      <dd data-testid="activity-pdu-state">{pdu.state ?? '—'}</dd>
      <dt className="text-text-secondary">IP</dt>
      <dd className="mono" data-testid="activity-pdu-ip">
        {pdu.address ?? '—'}
      </dd>
    </dl>
  );
}

function ThroughputBlock({
  counters,
  samples,
}: {
  counters: ActivityCounters | null;
  samples: Sample[];
}) {
  if (!counters) {
    return <p className="text-ep-sm text-text-secondary">Compteurs uesimtun indisponibles.</p>;
  }
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat
          label="UL cumul"
          value={formatBytes(counters.tx_bytes)}
          hint={`${counters.tx_packets.toLocaleString('fr-FR')} paquets`}
          testid="throughput-ul-cum"
        />
        <Stat
          label="UL débit"
          value={formatBps(counters.tx_bps)}
          hint="instantané"
          testid="throughput-ul-bps"
        />
        <Stat
          label="DL cumul"
          value={formatBytes(counters.rx_bytes)}
          hint={`${counters.rx_packets.toLocaleString('fr-FR')} paquets`}
          testid="throughput-dl-cum"
        />
        <Stat
          label="DL débit"
          value={formatBps(counters.rx_bps)}
          hint="instantané"
          testid="throughput-dl-bps"
        />
      </div>
      <Sparkline samples={samples} />
    </div>
  );
}

function Stat({
  label,
  value,
  hint,
  testid,
}: {
  label: string;
  value: string;
  hint: string;
  testid: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-canvas p-3" data-testid={testid}>
      <p className="text-ep-xs uppercase tracking-wider text-text-secondary">{label}</p>
      <p className="text-ep-lg mono font-semibold">{value}</p>
      <p className="text-ep-xs text-text-secondary">{hint}</p>
    </div>
  );
}

function Sparkline({ samples }: { samples: Sample[] }) {
  const width = 600;
  const height = 80;
  if (samples.length < 2) {
    return (
      <p className="text-ep-xs text-text-secondary" data-testid="sparkline-empty">
        En attente de données (sparkline construit sur 2 min)…
      </p>
    );
  }
  const maxBps = Math.max(
    1,
    ...samples.flatMap((sample) => [sample.rx_bps, sample.tx_bps]),
  );
  const stepX = width / (MAX_SAMPLES - 1);
  const build = (pick: (sample: Sample) => number) =>
    samples
      .map((sample, index) => {
        const x = index * stepX;
        const y = height - (pick(sample) / maxBps) * (height - 4) - 2;
        return `${index === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className="w-full h-20"
      aria-label="UL/DL sparkline over 2 minutes"
      data-testid="sparkline"
    >
      <rect x={0} y={0} width={width} height={height} className="fill-canvas" />
      <path d={build((sample) => sample.rx_bps)} className="stroke-primary" fill="none" strokeWidth={1.5} />
      <path d={build((sample) => sample.tx_bps)} className="stroke-success" fill="none" strokeWidth={1.5} />
    </svg>
  );
}

function JobBlock({ jobStep }: { jobStep: ActivityJobStep | null }) {
  if (!jobStep) {
    return <p className="text-ep-sm text-text-secondary">Aucun job actif sur cette UE.</p>;
  }
  return (
    <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-ep-sm">
      <dt className="text-text-secondary">Job</dt>
      <dd className="mono truncate" data-testid="activity-job-id">
        {jobStep.job_id ?? '—'}
      </dd>
      <dt className="text-text-secondary">Définition</dt>
      <dd className="mono truncate" data-testid="activity-job-definition">
        {jobStep.definition_id ?? '—'}
      </dd>
      <dt className="text-text-secondary">État</dt>
      <dd data-testid="activity-job-state">{jobStep.state ?? '—'}</dd>
      <dt className="text-text-secondary">Étape</dt>
      <dd data-testid="activity-job-step">
        {jobStep.current_step
          ? `#${jobStep.current_step.index} · ${jobStep.current_step.type} · ${jobStep.current_step.state}`
          : '—'}
      </dd>
    </dl>
  );
}

function TimelineBlock({ events }: { events: ActivityEvent[] }) {
  if (events.length === 0) {
    return <p className="text-ep-sm text-text-secondary">Aucun événement récent.</p>;
  }
  return (
    <ol className="flex flex-col gap-1 text-ep-sm" data-testid="timeline-list">
      {events
        .slice()
        .reverse()
        .map((event, index) => (
          <li
            key={`${event.epoch_s}-${index}`}
            className="flex items-center justify-between gap-3 border-b border-border/60 last:border-b-0 py-1"
            data-testid={`timeline-item-${index}`}
          >
            <span className="mono text-ep-xs text-text-secondary">
              {new Date(event.epoch_s * 1_000).toLocaleTimeString('fr-FR')}
            </span>
            <span className="flex-1 min-w-0 truncate">
              <span className="font-medium">{event.kind}</span>
              {event.outcome && ` · ${event.outcome}`}
            </span>
            <span
              className={`ep-badge text-ep-xs ${
                event.outcome === 'OK'
                  ? 'border-success/40 text-success'
                  : event.outcome === 'FAILED'
                    ? 'border-error/40 text-error'
                    : 'border-border text-text-secondary'
              }`}
            >
              {event.outcome}
            </span>
          </li>
        ))}
    </ol>
  );
}

function LiveIndicator({ status }: { status: 'connecting' | 'live' | 'reconnecting' }) {
  const tone =
    status === 'live' ? 'bg-success' : status === 'reconnecting' ? 'bg-warning' : 'bg-text-secondary';
  const label =
    status === 'live' ? 'en direct' : status === 'reconnecting' ? 'reconnexion…' : 'connexion…';
  return (
    <span
      className="inline-flex items-center gap-2 text-ep-xs text-text-secondary"
      data-testid="activity-live"
      data-status={status}
    >
      <span className={`h-2 w-2 rounded-full ${tone}`} aria-hidden="true" />
      {label}
    </span>
  );
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null) return '—';
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const exponent = Math.min(units.length - 1, Math.floor(Math.log10(Math.max(1, bytes)) / 3));
  const value = bytes / 1_000 ** exponent;
  return `${value.toFixed(exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}

export function formatBps(bps: number | null | undefined): string {
  if (bps == null) return '—';
  if (bps === 0) return '0 b/s';
  const bits = bps * 8;
  const units = ['b/s', 'kb/s', 'Mb/s', 'Gb/s'];
  const exponent = Math.min(units.length - 1, Math.floor(Math.log10(Math.max(1, bits)) / 3));
  const value = bits / 1_000 ** exponent;
  return `${value.toFixed(exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}
