// 2.4.0 — Sessions page rebuilt to match docs/ui-mockups/oiran-analyzer.html.
//
// Fix for the reported Session ID overlap bug: the Procedure cell now
// carries the mono session hash on a second mute line, wrapped in a
// `max-w-[260px] truncate` + `title={session_id}` so the full identifier
// is reachable on hover but never bleeds into UE / Start / Interfaces /
// Correlation at 1280 / 1440 / 1920. The explicit "Session ID" column is
// gone — the hash lives under the procedure, exactly like the mockup.
//
// Columns (7 content cols + checkbox hidden; mockup contract):
//   Procedure · UE · Start (UTC) · Duration · Interfaces · Msgs · Correlation
//
// Subscriber identity rule: UE column stays on the backend pseudonym
// (never resolved to IMSI / IMEI / TMSI / GUTI).

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { Waypoints } from 'lucide-react';
import { api } from '../services/api';
import type { ApiEnvelope, Dataset, Session } from '../types/api';
import { ErrorState, LoadingState, EmptyState } from '../components/AsyncState';
import {
  Btn,
  Card,
  IfChip,
  PageHeader,
  Pill,
  confTone,
} from '../components/mockup';
import { formatTimestampUtc } from '../utils/time';

function formatDuration(ns: string): string {
  const n = Number(ns);
  if (!Number.isFinite(n)) return '—';
  if (n < 1_000_000_000) return `${(n / 1_000_000).toFixed(0)} ms`;
  return `${(n / 1_000_000_000).toFixed(3)} s`;
}

interface DetailResponse {
  summary: Session;
  procedures: { name: string; event_ids: string[]; status: string }[];
  accounting: Record<string, number>;
  capture_references: string[];
}

export function SessionExplorer() {
  const route = useParams();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [sessionPage, setSessionPage] = useState(Number(params.get('page') ?? 1));

  const datasetId = params.get('dataset_id') ?? '';
  const iface = params.get('interface') ?? '';
  const correlation = params.get('correlation') ?? '';
  const search = params.get('search') ?? '';

  const datasets = useQuery({
    queryKey: ['datasets'],
    queryFn: () => api<Dataset[]>('/datasets?page_size=100').then((x) => x.data),
  });

  const sessionQuery = useMemo(() => {
    const q = new URLSearchParams({
      page: String(sessionPage),
      page_size: '25',
      sort: 'start_timestamp',
      order: 'desc',
    });
    if (datasetId) q.set('dataset_id', datasetId);
    if (iface) q.set('interface', iface);
    if (correlation) q.set('correlation', correlation);
    if (search) q.set('search', search);
    return q;
  }, [sessionPage, datasetId, iface, correlation, search]);

  const sessions = useQuery({
    queryKey: ['sessions', sessionQuery.toString()],
    queryFn: () =>
      api<Session[]>(`/sessions?${sessionQuery}`).then((x) => x as ApiEnvelope<Session[]>),
  });

  const rows = sessions.data?.data ?? [];
  const selectedId = route.sessionId ?? rows[0]?.session_id;
  const selected = selectedId
    ? rows.find((r) => r.session_id === selectedId) ?? rows[0]
    : rows[0];

  const detail = useQuery({
    queryKey: ['session-detail', selected?.session_id],
    queryFn: () =>
      api<DetailResponse>(`/sessions/${selected!.session_id}`).then((x) => x.data),
    enabled: !!selected?.session_id,
  });

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete('page');
    setSessionPage(1);
    setParams(next);
  }

  function openCallFlow(session: Session) {
    const next = new URLSearchParams(params);
    next.set('dataset_id', session.dataset_id);
    navigate(`/investigation/callflow/${encodeURIComponent(session.session_id)}?${next}`);
  }

  function selectRow(session: Session) {
    const next = new URLSearchParams(params);
    next.set('dataset_id', session.dataset_id);
    navigate(`/investigation/sessions/${encodeURIComponent(session.session_id)}?${next}`);
  }

  if (sessions.isLoading || datasets.isLoading) return <LoadingState />;
  const error = sessions.error || datasets.error;
  if (error)
    return (
      <ErrorState
        error={error as Error}
        retry={() => {
          void sessions.refetch();
          void datasets.refetch();
        }}
      />
    );

  const total = selected
    ? selected.decode_completeness.decoded +
      selected.decode_completeness.partial +
      (selected.message_count -
        selected.decode_completeness.decoded -
        selected.decode_completeness.partial)
    : 1;
  const protectedCount = selected
    ? selected.message_count -
      selected.decode_completeness.decoded -
      selected.decode_completeness.partial
    : 0;

  return (
    <>
      <PageHeader
        eyebrow="Investigate"
        title="Sessions"
        desc="UE contexts and PDU sessions reconstructed from the captured signalling. UEs appear only as pseudonyms."
        actions={
          selected ? (
            <Btn
              icon={Waypoints}
              primary
              onClick={() => openCallFlow(selected)}
              data-testid="sessions-open-callflow"
            >
              Open call flow
            </Btn>
          ) : undefined
        }
      />

      <div className="flex flex-wrap gap-2">
        <select
          aria-label="Dataset"
          value={datasetId}
          onChange={(e) => setParam('dataset_id', e.target.value)}
          className="h-9 px-3 rounded-md border border-line bg-surface text-md2 text-ink"
          data-testid="sessions-dataset-filter"
        >
          <option value="">All datasets</option>
          {datasets.data?.map((d) => (
            <option key={d.dataset_id} value={d.dataset_id}>
              {d.display_name}
            </option>
          ))}
        </select>
        <select
          aria-label="Interface"
          value={iface}
          onChange={(e) => setParam('interface', e.target.value)}
          className="h-9 px-3 rounded-md border border-line bg-surface text-md2 text-ink"
          data-testid="sessions-interface-filter"
        >
          <option value="">All interfaces</option>
          {['N2', 'SBI', 'N4', 'N3'].map((i) => (
            <option key={i} value={i}>
              {i}
            </option>
          ))}
        </select>
        <select
          aria-label="Correlation"
          value={correlation}
          onChange={(e) => setParam('correlation', e.target.value)}
          className="h-9 px-3 rounded-md border border-line bg-surface text-md2 text-ink"
          data-testid="sessions-correlation-filter"
        >
          <option value="">Any correlation</option>
          <option value="STRONG">Exact / strong</option>
          <option value="POSSIBLE">Possible</option>
          <option value="UNKNOWN">Unknown</option>
        </select>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px] items-start">
        <Card className="overflow-hidden">
          {rows.length === 0 ? (
            <EmptyState title="No sessions match these filters" />
          ) : (
            <div className="overflow-x-auto">
              <table
                className="w-full min-w-[760px] text-md2 table-fixed"
                data-testid="sessions-table"
              >
                <colgroup>
                  <col style={{ width: '26%' }} />
                  <col style={{ width: '13%' }} />
                  <col style={{ width: '18%' }} />
                  <col style={{ width: '9%' }} />
                  <col style={{ width: '14%' }} />
                  <col style={{ width: '7%' }} />
                  <col style={{ width: '13%' }} />
                </colgroup>
                <thead>
                  <tr className="text-left text-xs2 uppercase tracking-wider text-mute border-b border-line">
                    <th className="px-4 py-2.5 font-semibold">Procedure</th>
                    <th className="px-3 py-2.5 font-semibold">UE</th>
                    <th className="px-3 py-2.5 font-semibold">Start (UTC)</th>
                    <th className="px-3 py-2.5 font-semibold text-right">Duration</th>
                    <th className="px-3 py-2.5 font-semibold">Interfaces</th>
                    <th className="px-3 py-2.5 font-semibold text-right">Msgs</th>
                    <th className="px-3 py-2.5 font-semibold">Correlation</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr
                      key={r.session_id}
                      onClick={() => selectRow(r)}
                      aria-selected={selected?.session_id === r.session_id}
                      data-testid={`session-row-${r.session_id}`}
                      className={`border-b border-line last:border-0 cursor-pointer ${
                        selected?.session_id === r.session_id
                          ? 'bg-brand-soft'
                          : 'hover:bg-canvas'
                      }`}
                    >
                      <td className="px-4 py-3 max-w-[260px] overflow-hidden">
                        {/* 2.4.0 fix: Procedure + mono session hash on a
                            second mute line. The wrapper locks the cell
                            to max-w-[260px] + truncate so the long hash
                            never bleeds into neighbour columns at 1280
                            / 1440 / 1920. `title` reveals the full id. */}
                        <p className="font-medium truncate" title={r.procedure}>
                          {r.procedure}
                        </p>
                        <p
                          className="mono text-xs2 text-mute truncate"
                          data-testid={`session-id-${r.session_id}`}
                          title={r.session_id}
                        >
                          {r.session_id}
                          {r.serving_node ? ` · ${r.serving_node}` : ''}
                        </p>
                      </td>
                      <td
                        className="px-3 py-3 mono text-sm2 whitespace-nowrap overflow-hidden text-ellipsis"
                        title={r.ue_pseudonym}
                      >
                        {r.ue_pseudonym}
                      </td>
                      <td className="px-3 py-3 mono text-sm2 whitespace-nowrap">
                        {formatTimestampUtc(r.start_timestamp)}
                      </td>
                      <td className="px-3 py-3 mono text-right whitespace-nowrap">
                        {formatDuration(r.duration_ns)}
                      </td>
                      <td className="px-3 py-3">
                        <span className="flex gap-1 flex-wrap">
                          {r.interfaces.map((i) => (
                            <IfChip key={i} i={i} />
                          ))}
                        </span>
                      </td>
                      <td className="px-3 py-3 mono text-right">{r.message_count}</td>
                      <td className="px-3 py-3">
                        <Pill tone={confTone(r.correlation_status)}>
                          {r.correlation_status}
                        </Pill>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="flex items-center justify-between px-4 py-2.5 border-t border-line text-sm2 text-mute">
            <span>
              {sessions.data?.meta.total ?? rows.length} sessions
            </span>
            <span>
              Page {sessions.data?.meta.page ?? 1} of{' '}
              {sessions.data?.meta.total_pages ?? 1}
            </span>
          </div>
        </Card>

        {selected ? (
          <Card
            className="p-5 flex flex-col gap-4 xl:sticky xl:top-4"
            data-testid="sessions-detail"
          >
            <div>
              <p className="text-xs2 font-semibold uppercase tracking-wider text-mute">
                Selected session
              </p>
              <h2 className="text-xl2 font-semibold">{selected.procedure}</h2>
              <p className="mono text-xs2 text-mute break-all" title={selected.session_id}>
                {selected.session_id}
              </p>
            </div>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
              <div className="min-w-0">
                <dt className="text-xs2 uppercase tracking-wider text-mute">UE pseudonym</dt>
                <dd className="mono text-sm2 truncate" title={selected.ue_pseudonym}>
                  {selected.ue_pseudonym}
                </dd>
              </div>
              <div className="min-w-0">
                <dt className="text-xs2 uppercase tracking-wider text-mute">PDU session</dt>
                <dd className="mono text-sm2">{selected.pdu_session_id}</dd>
              </div>
              <div className="min-w-0">
                <dt className="text-xs2 uppercase tracking-wider text-mute">Serving node</dt>
                <dd className="mono text-sm2 truncate">{selected.serving_node ?? '—'}</dd>
              </div>
              <div className="min-w-0">
                <dt className="text-xs2 uppercase tracking-wider text-mute">Technology</dt>
                <dd className="text-sm2">{selected.technology}</dd>
              </div>
              <div className="min-w-0">
                <dt className="text-xs2 uppercase tracking-wider text-mute">Duration</dt>
                <dd className="mono text-sm2">{formatDuration(selected.duration_ns)}</dd>
              </div>
              <div className="min-w-0">
                <dt className="text-xs2 uppercase tracking-wider text-mute">
                  Background events
                </dt>
                <dd className="mono text-sm2">{selected.background_event_count}</dd>
              </div>
            </dl>
            <dl className="grid gap-y-3">
              <div className="min-w-0">
                <dt className="text-xs2 uppercase tracking-wider text-mute">Start (UTC)</dt>
                <dd className="mono text-sm2">{formatTimestampUtc(selected.start_timestamp)}</dd>
              </div>
              <div className="min-w-0">
                <dt className="text-xs2 uppercase tracking-wider text-mute">Dataset</dt>
                <dd className="mono text-sm2 truncate" title={selected.dataset_id}>
                  {selected.dataset_id}
                </dd>
              </div>
            </dl>
            <div>
              <p className="text-xs2 font-semibold uppercase tracking-wider text-mute mb-1.5">
                Decode completeness · {selected.message_count} messages
              </p>
              <div
                className="flex h-2 rounded-full overflow-hidden bg-track"
                role="img"
                aria-label={`${selected.decode_completeness.decoded} decoded, ${selected.decode_completeness.partial} partial, ${protectedCount} protected`}
              >
                <div
                  className="bg-ok"
                  style={{ width: `${(selected.decode_completeness.decoded / total) * 100}%` }}
                />
                <div
                  className="bg-warn"
                  style={{ width: `${(selected.decode_completeness.partial / total) * 100}%` }}
                />
                <div
                  className="bg-vio"
                  style={{ width: `${(protectedCount / total) * 100}%` }}
                />
              </div>
              <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-sm2 text-mute">
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-ok" />
                  Decoded {selected.decode_completeness.decoded}
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-warn" />
                  Partial {selected.decode_completeness.partial}
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-vio" />
                  NAS protected {protectedCount}
                </span>
              </div>
            </div>
            <div className="flex flex-wrap gap-2 border-t border-line pt-3">
              <Btn icon={Waypoints} primary onClick={() => openCallFlow(selected)}>
                Call flow
              </Btn>
              <Link
                to={`/investigation/correlation/${encodeURIComponent(selected.session_id)}`}
                className="inline-flex items-center gap-1.5 h-9 px-4 rounded-md text-md2 font-medium border border-line bg-surface hover:bg-canvas text-ink"
              >
                Correlation
              </Link>
            </div>
            {detail.isLoading ? (
              <p className="text-xs2 text-mute">Loading detail…</p>
            ) : null}
          </Card>
        ) : null}
      </div>
    </>
  );
}
