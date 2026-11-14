// 0.36.0 — « Suivi UE » : monitoring page from the user's mockup.
// One SSE stream (/ues/:id/activity/stream) + a single snapshot GET as
// fallback. Shows RRC, 5GMM/RM, PDU + IP, current scenario step,
// DL/UL throughput chart, IMS state and the event timeline.

import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Card, PageHeader } from '@/components/mockup';
import { polarisApi } from '@/data/polarisClient';
import { useStopScenario } from '@/data/queries';
import type { UeActivityPayload } from '@/pages/UeActivity';
import { Badge, Kpi, ThroughputChart, formatBps, formatBytes, hhmmss, type RateSample, type Tone } from './labShared';

const MAX_SAMPLES = 60;

export function toneFor(value: string | null | undefined): Tone {
  const v = (value ?? '').toUpperCase();
  if (!v) return 'idle';
  if (/(CONNECTED|REGISTERED|ACTIVE|ESTABLISHED|RUNNING|OK|SUCCE)/.test(v) && !/(DE-?REGISTERED|NOT|IN-?ACTIVE)/.test(v)) return 'ok';
  if (/(FAIL|ERROR|REJECT)/.test(v)) return 'bad';
  if (/(IDLE|PENDING|INIT|PROGRESS)/.test(v)) return 'warn';
  return 'idle';
}

export function nextSamples(prev: RateSample[], data: UeActivityPayload): RateSample[] {
  const c = data.counters;
  if (!c || (c.rx_bps == null && c.tx_bps == null)) return prev;
  // rx = DL seen by the UE, tx = UL.
  return [...prev, { dl: c.rx_bps ?? 0, ul: c.tx_bps ?? 0 }].slice(-MAX_SAMPLES);
}

export function LabUeMonitorPage() {
  const { ueId = '' } = useParams();
  const [payload, setPayload] = useState<UeActivityPayload | null>(null);
  const [samples, setSamples] = useState<RateSample[]>([]);
  const [live, setLive] = useState<'connexion' | 'en direct' | 'reconnexion'>('connexion');
  const [error, setError] = useState<string | null>(null);
  const stop = useStopScenario();

  useEffect(() => {
    if (!ueId) return;
    let cancelled = false;
    const apply = (data: UeActivityPayload) => {
      if (cancelled) return;
      setPayload(data);
      setSamples((prev) => nextSamples(prev, data));
    };
    const snapshot = () =>
      polarisApi<UeActivityPayload>(`/ues/${encodeURIComponent(ueId)}/activity`)
        .then(apply)
        .catch((e: Error) => !cancelled && setError(e.message));
    void snapshot();
    let source: EventSource | null = null;
    if (typeof EventSource !== 'undefined') {
      source = new EventSource(`/polaris-api/v1/ues/${encodeURIComponent(ueId)}/activity/stream`, { withCredentials: true });
      source.onopen = () => setLive('en direct');
      source.onerror = () => setLive('reconnexion');
      source.onmessage = (ev) => {
        try {
          apply(JSON.parse(ev.data) as UeActivityPayload);
          setError(null);
        } catch {
          /* ignore malformed frame */
        }
      };
    }
    const fallback = window.setInterval(() => {
      if (source && source.readyState === EventSource.OPEN) return;
      void snapshot();
    }, 5000);
    return () => {
      cancelled = true;
      source?.close();
      window.clearInterval(fallback);
    };
  }, [ueId]);

  const st = payload?.states ?? {};
  const pdus = payload?.pdus?.length ? payload.pdus : payload?.pdu ? [payload.pdu] : [];
  const job = payload?.job_step ?? null;
  const events = useMemo(() => [...(payload?.events ?? [])].sort((a, b) => b.epoch_s - a.epoch_s).slice(0, 30), [payload?.events]);
  const voice = payload?.voice;

  return (
    <>
      <PageHeader
        eyebrow="Suivi UE"
        title={ueId}
        desc={`IMSI ${payload?.imsi ?? '--'} · flux ${live}`}
        actions={
          <div className="flex gap-2">
            <Link to="/lab/ues" className="inline-flex items-center h-10 px-4 rounded-md border border-line text-ep-md">
              ← UE du lab
            </Link>
            {job?.job_id && job.state && !/(COMPLETED|FAILED|STOPPED)/.test(job.state) && (
              <button
                type="button"
                className="h-10 px-4 rounded-md border border-bad text-bad font-semibold"
                disabled={stop.isPending}
                onClick={() => stop.mutate(job.job_id as string)}
                data-testid="monitor-stop"
              >
                Arrêter le scénario
              </button>
            )}
          </div>
        }
      />
      {error && !payload && <p className="text-bad text-ep-sm">Suivi indisponible : {error}</p>}
      {payload && !payload.running && (
        <p className="text-ep-sm text-mute" data-testid="monitor-not-running">
          UE arrêté{payload.reason ? ` — ${payload.reason}` : ''}. Lance un scénario depuis « UE du lab ».
        </p>
      )}

      <div className="grid gap-3 grid-cols-2 lg:grid-cols-4" data-testid="monitor-kpis">
        <Kpi label="RRC" value={<Badge tone={toneFor(st.rrc_state)}>{st.rrc_state ?? '--'}</Badge>} />
        <Kpi
          label="Enregistrement (5GMM / RM)"
          value={<Badge tone={toneFor(st.rm_state ?? st.mm_5g_state)}>{st.rm_state ?? st.mm_5g_state ?? '--'}</Badge>}
          sub={st.mm_5g_state ?? undefined}
        />
        <Kpi
          label="Session PDU"
          value={<Badge tone={toneFor(pdus[0]?.state)}>{pdus[0]?.state ?? 'aucune'}</Badge>}
          sub={pdus.map((p) => `${p.dnn ?? '?'} · ${p.address ?? 'sans IP'}`).join(' | ') || undefined}
        />
        <Kpi
          label="Scénario"
          value={job?.definition_id ?? '--'}
          sub={job?.current_step ? `étape ${job.current_step.index + 1} · ${job.current_step.type} · ${job.current_step.state}` : job?.state ?? 'aucun run'}
        />
      </div>

      <div className="grid gap-3 lg:grid-cols-[2fr_1fr]">
        <Card className="p-4 flex flex-col gap-3">
          <div className="flex items-baseline justify-between">
            <h2 className="text-ep-lg font-semibold">Débit</h2>
            <span className="text-ep-sm text-mute">
              DL {formatBps(payload?.counters?.rx_bps)} · UL {formatBps(payload?.counters?.tx_bps)}
            </span>
          </div>
          <ThroughputChart samples={samples} testid="monitor-chart" />
          <div className="grid grid-cols-2 gap-3 text-ep-sm">
            <Kpi label="Total DL reçu" value={formatBytes(payload?.counters?.rx_bytes)} sub={payload?.counters?.interface ?? undefined} />
            <Kpi label="Total UL envoyé" value={formatBytes(payload?.counters?.tx_bytes)} />
          </div>
        </Card>
        <Card className="p-4 flex flex-col gap-3">
          <h2 className="text-ep-lg font-semibold">Voix / IMS</h2>
          <Badge tone={voice?.available ? 'ok' : 'idle'}>{voice?.available ? 'IMS enregistré' : 'IMS non enregistré'}</Badge>
          <p className="text-ep-xs text-mute">{voice?.reason ?? voice?.detail ?? '--'}{voice?.sip_code ? ` · SIP ${voice.sip_code}` : ''}</p>
        </Card>
      </div>

      <Card className="p-4">
        <h2 className="text-ep-lg font-semibold mb-2">Journal</h2>
        {events.length === 0 ? (
          <p className="text-ep-sm text-mute">-- (aucun événement)</p>
        ) : (
          <ol className="flex flex-col divide-y divide-line" data-testid="monitor-timeline">
            {events.map((e, i) => (
              <li key={`${e.epoch_s}-${i}`} className="flex gap-3 py-2 text-ep-sm">
                <span className="font-mono text-mute w-20 shrink-0">{hhmmss(e.epoch_s)}</span>
                <span className="font-semibold w-48 shrink-0">{e.kind}</span>
                <Badge tone={toneFor(e.outcome)}>{e.outcome}</Badge>
              </li>
            ))}
          </ol>
        )}
      </Card>
    </>
  );
}
