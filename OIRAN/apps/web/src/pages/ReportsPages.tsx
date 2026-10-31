// 2.4.0 — Exports page rebuilt to match docs/ui-mockups/oiran-analyzer.html.
// The mockup lists export types, not per-session cards:
//   - Call flow · HTML       (active, uses /exports/callflow/:id?format=html)
//   - Call flow · JSON       (active, uses /exports/callflow/:id?format=json)
//   - Session summary · CSV  (active, derived from /sessions on the client)
//   - PCAP slice of a session (LOCKED — needs /captures/:id/download which
//     returns 404 today, per docs/ui-mockups/README.md backend reality.)
//
// Live Monitoring stays under /reports/monitoring (dropped from the
// primary nav but reachable by URL).

import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Download, HardDrive, Radio, FileText } from 'lucide-react';
import { api, downloadExport } from '../services/api';
import type { Metrics, Session } from '../types/api';
import { ErrorState, LoadingState } from '../components/AsyncState';
import { StatusBadge } from '../components/StatusBadge';
import { Btn, Card, Locked, PageHeader } from '../components/mockup';

interface Row {
  key: string;
  title: string;
  desc: string;
  format?: 'html' | 'json' | 'csv';
  lockedReason?: string;
}

const ROWS: Row[] = [
  {
    key: 'callflow-html',
    title: 'Call flow · HTML',
    desc: 'Self-contained page of the ladder, IE trees and correlation (one session).',
    format: 'html',
  },
  {
    key: 'callflow-json',
    title: 'Call flow · JSON',
    desc: 'callflow-schema document with events, edges and accounting (one session).',
    format: 'json',
  },
  {
    key: 'session-csv',
    title: 'Session summary · CSV',
    desc: 'One row per session for the current filters. Composed client-side from /sessions.',
    format: 'csv',
  },
  {
    key: 'pcap-slice',
    title: 'PCAP slice of a session',
    desc: 'Only the frames of one session, from the source captures.',
    lockedReason:
      'Needs GET /captures/:id/download, which the backend returns 404 for today.',
  },
];

function sessionsToCsv(sessions: Session[]): string {
  const header =
    'session_id,ue_pseudonym,technology,procedure,start_timestamp,duration_ns,interfaces,message_count,correlation_status';
  const lines = sessions.map((s) =>
    [
      s.session_id,
      s.ue_pseudonym,
      s.technology,
      JSON.stringify(s.procedure),
      s.start_timestamp,
      s.duration_ns,
      JSON.stringify(s.interfaces.join('|')),
      s.message_count,
      s.correlation_status,
    ].join(','),
  );
  return [header, ...lines].join('\n');
}

export function ExportReports() {
  const navigate = useNavigate();
  const sessions = useQuery({
    queryKey: ['sessions-export'],
    queryFn: () => api<Session[]>('/sessions?page_size=100').then((x) => x.data),
  });

  if (sessions.isLoading) return <LoadingState />;
  if (sessions.error)
    return (
      <ErrorState
        error={sessions.error as Error}
        retry={() => void sessions.refetch()}
      />
    );
  const rows = sessions.data ?? [];
  const first = rows[0];

  async function trigger(row: Row) {
    if (row.lockedReason || !row.format) return;
    if (!first) return;
    if (row.format === 'csv') {
      const csv = sessionsToCsv(rows);
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `oiran-sessions-${Date.now()}.csv`;
      anchor.click();
      URL.revokeObjectURL(url);
      return;
    }
    await downloadExport(first.session_id, row.format);
  }

  return (
    <>
      <PageHeader
        eyebrow="Evidence"
        title="Exports"
        desc="Take evidence out of the analyzer. Exports never contain subscriber identities."
        actions={
          first ? (
            <Btn onClick={() => navigate(`/investigation/callflow/${encodeURIComponent(first.session_id)}`)}>
              Pick session
            </Btn>
          ) : undefined
        }
      />
      <Card className="overflow-hidden" data-testid="exports-list">
        <ul className="divide-y divide-line">
          {ROWS.map((row) => (
            <li
              key={row.key}
              className="px-5 py-4 flex flex-wrap items-center justify-between gap-3"
              data-testid={`export-row-${row.key}`}
            >
              <div className="min-w-0">
                <p className="font-medium">{row.title}</p>
                <p className="text-sm2 text-mute">{row.desc}</p>
                {!first ? (
                  <p className="mt-1 text-xs2 text-mute">
                    No session available yet; filters have returned 0 results.
                  </p>
                ) : null}
              </div>
              {row.lockedReason ? (
                <Locked reason={row.lockedReason} data-testid={`export-locked-${row.key}`}>
                  Export
                </Locked>
              ) : (
                <Btn
                  icon={row.format === 'csv' ? FileText : Download}
                  primary={row.format === 'json'}
                  onClick={() => void trigger(row)}
                  disabled={!first}
                  data-testid={`export-trigger-${row.key}`}
                >
                  {row.format === 'csv' ? 'Download CSV' : 'Export'}
                </Btn>
              )}
            </li>
          ))}
        </ul>
      </Card>
      <p className="text-sm2 text-mute">
        HTML and JSON exports target the first session in the current filter set
        ({first ? first.session_id : '—'}). To export a different session, pick
        it in the Sessions page first — the Exports page will offer it on the
        next load.
      </p>
    </>
  );
}

const shown = (value: number | null | undefined, unit = '') =>
  value == null ? 'NOT AVAILABLE' : `${value.toLocaleString()}${unit}`;
const bytes = (v: number | null | undefined) =>
  v == null ? 'NOT AVAILABLE' : `${(v / 1073741824).toFixed(1)} GiB`;

export function LiveMonitoring() {
  const metrics = useQuery({
    queryKey: ['metrics-live'],
    queryFn: () => api<Metrics>('/metrics').then((x) => x.data),
    refetchInterval: 5000,
  });
  if (metrics.isLoading) return <LoadingState />;
  if (metrics.error)
    return (
      <ErrorState
        error={metrics.error as Error}
        retry={() => void metrics.refetch()}
      />
    );
  const m = metrics.data;
  return (
    <div className="page-stack">
      <section className="page-intro">
        <div>
          <p className="eyebrow">REPORTS</p>
          <h1>Live Monitoring</h1>
          <p>Measured host state and explicit availability of capture telemetry.</p>
        </div>
        <div className="header-actions">
          <StatusBadge value={m?.mode ?? 'UNKNOWN'} />
          <span className="updated">5 second refresh</span>
        </div>
      </section>
      <section className="monitor-grid">
        <Monitor label="Packet rate" value={shown(m?.packet_rate_pps, ' pps')} note="No live capture source" />
        <Monitor label="Bitrate" value={shown(m?.bitrate_bps, ' bps')} note="No live capture source" />
        <Monitor label="Decode throughput" value={shown(m?.decode_rate_eps, ' eps')} note="Offline decoder idle" />
        <Monitor label="Packet drops" value={shown(m?.packet_drops)} note="Counter not exported" />
        <Monitor
          label="CPU"
          value={m?.cpu.usage_percent == null ? `Load ${m?.cpu.load_one ?? '—'}` : `${m.cpu.usage_percent.toFixed(1)}%`}
          note={`${m?.cpu.logical_cpus ?? '—'} available CPU`}
        />
        <Monitor label="Memory used" value={bytes(m?.memory.used_bytes)} note={`${bytes(m?.memory.available_bytes)} available`} />
        <Monitor
          label="Disk usage"
          value={m?.disk ? `${m.disk.usage_percent.toFixed(1)}%` : 'NOT AVAILABLE'}
          note={`${bytes(m?.disk?.available_bytes)} available`}
        />
        <Monitor label="Capture queue" value={shown(m?.capture_queue_utilization_percent, '%')} note="Queue not configured" />
      </section>
      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Interface telemetry</h2>
            <p>Empty telemetry is preserved as unavailable rather than estimated.</p>
          </div>
          <Radio />
        </div>
        <div className="interface-health">
          {m?.interfaces.map((item) => (
            <article key={item.interface}>
              <b>{item.interface}</b>
              <StatusBadge value={item.state} />
              <span>{shown(item.packet_rate_pps, ' pps')}</span>
            </article>
          ))}
        </div>
        <div className="monitor-empty">
          <HardDrive />
          <div>
            <b>No live capture time series</b>
            <p>
              The vProbe is serving immutable historical analysis. Configure
              and certify a bounded capture backend before charts can display
              live traffic.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}

function Monitor({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <article className="panel monitor-card">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{note}</small>
    </article>
  );
}
