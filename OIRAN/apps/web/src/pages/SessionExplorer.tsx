// 2.5.0 — Sessions page.
//
// Visual contract: docs/ui-mockups/oiran-analyzer.html — 7 content columns
// (Procedure · UE · Start (UTC) · Duration · Interfaces · Msgs · Correlation).
// The explicit Session ID column is removed; the mono hash sits on a second
// mute line of the Procedure cell, locked inside max-w-[260px] + truncate +
// title={session_id}. This fixes the pre-2.4 overlap bug at 1280 / 1440 /
// 1920 (covered by e2e-2.4.0/no-overlap-sessions.spec.ts).
//
// Honesty gates kept from 2.3 / 2.4.1-dev (session-context.test.tsx):
// - /captures/:id/context "DATASET_UNAVAILABLE" → full-page error, never a
//   silent historical fallback.
// - zero-session empty state (`No reconstructed sessions in this capture.`)
//   with the "View Packets" link.
// - categorised dataset filter with the four scope buckets (HISTORICAL,
//   CAPTURED_LIVE, RECOVERED, DERIVED) + explicit `scope:*` option values.
// - URL params preserved: capture_id, dataset_id, dataset_scope, probe_id,
//   technology, interface, status, ue.
//
// Subscriber identity rule: UE column stays on the backend pseudonym, never
// resolves IMSI / IMEI / TMSI / GUTI / RNTI / K / OPc.

import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { FileSearch, ListTree, Waypoints } from 'lucide-react';
import { api } from '../services/api';
import type { ApiEnvelope, CaptureContext, Dataset, Session, UeContext } from '../types/api';
import { ErrorState, LoadingState, EmptyState } from '../components/AsyncState';
import {
  Btn,
  Card,
  IfChip,
  PageHeader,
  Pill,
  confTone,
} from '../components/mockup';
import { Pagination } from '../components/Pagination';
import { formatTimestampUtc } from '../utils/time';

function formatDuration(ns: string): string {
  const n = Number(ns);
  if (!Number.isFinite(n)) return '—';
  if (n < 1_000_000_000) return `${(n / 1_000_000).toFixed(0)} ms`;
  return `${(n / 1_000_000_000).toFixed(3)} s`;
}

const queryString = (p: URLSearchParams) => (p.toString() ? `?${p}` : '');

export function SessionExplorer() {
  const navigate = useNavigate();
  const route = useParams();
  const [params, setParams] = useSearchParams();

  const [sessionPage, setSessionPage] = useState(Number(params.get('page') ?? 1));
  const captureId = params.get('capture_id') ?? '';
  const requestedDataset = params.get('dataset_id') ?? params.get('dataset') ?? '';
  const datasetScope = params.get('dataset_scope') ?? '';
  const probeId = params.get('probe_id') ?? '';
  const technology = params.get('technology') ?? '';
  const iface = params.get('interface') ?? '';
  const status = params.get('status') ?? '';
  const ue = params.get('ue') ?? '';
  const search = params.get('search') ?? '';
  const correlation = params.get('correlation') ?? '';

  const captureContext = useQuery({
    queryKey: ['capture-context', captureId],
    queryFn: () =>
      api<CaptureContext>(`/captures/${encodeURIComponent(captureId)}/context`).then(
        (x) => x.data,
      ),
    enabled: !!captureId,
  });
  const datasetId = requestedDataset || captureContext.data?.dataset?.dataset_id || '';
  const datasets = useQuery({
    queryKey: ['datasets'],
    queryFn: () => api<Dataset[]>('/datasets?page_size=100').then((x) => x.data),
  });
  const ues = useQuery({
    queryKey: ['ues'],
    queryFn: () => api<UeContext[]>('/ues?page_size=100').then((x) => x.data),
  });

  useEffect(() => {
    if (!requestedDataset && captureContext.data?.dataset?.dataset_id) {
      const next = new URLSearchParams(params);
      next.delete('dataset');
      next.delete('dataset_scope');
      next.set('dataset_id', captureContext.data.dataset.dataset_id);
      setParams(next, { replace: true });
    }
  }, [captureContext.data?.dataset?.dataset_id, requestedDataset, params, setParams]);

  const sessionQuery = useMemo(() => {
    const q = new URLSearchParams({
      page: String(sessionPage),
      page_size: '25',
      sort: 'start_timestamp',
      order: 'asc',
    });
    if (search) q.set('search', search);
    if (datasetId) q.set('dataset_id', datasetId);
    if (datasetScope) q.set('dataset_kind', datasetScope);
    if (ue) q.set('ue_id', ue);
    if (technology) q.set('technology', technology);
    if (iface) q.set('interface', iface);
    if (status) q.set('status', status);
    if (correlation) q.set('correlation', correlation);
    return q;
  }, [sessionPage, search, datasetId, datasetScope, ue, technology, iface, status, correlation]);

  const contextResolved = !captureId || !!datasetId;
  const sessions = useQuery({
    queryKey: ['sessions', sessionQuery.toString(), contextResolved],
    queryFn: () =>
      api<Session[]>(`/sessions?${sessionQuery}`).then((x) => x as ApiEnvelope<Session[]>),
    enabled: contextResolved,
  });

  const rows = sessions.data?.data ?? [];
  const selectedIdFromRoute = route.sessionId;
  const selected = selectedIdFromRoute
    ? rows.find((r) => r.session_id === selectedIdFromRoute) ?? rows[0]
    : rows[0];

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete('page');
    setSessionPage(1);
    setParams(next);
  }

  function updateDataset(value: string) {
    const next = new URLSearchParams(params);
    next.delete('dataset');
    next.delete('dataset_id');
    next.delete('dataset_scope');
    next.delete('capture_id');
    next.delete('probe_id');
    next.delete('page');
    next.delete('session_id');
    if (value.startsWith('scope:')) next.set('dataset_scope', value.slice(6));
    else if (value) next.set('dataset_id', value);
    setSessionPage(1);
    setParams(next);
  }

  function openSession(session: Session) {
    const next = new URLSearchParams(params);
    next.delete('page');
    next.delete('search');
    next.set('dataset_id', session.dataset_id);
    next.set('session_id', session.session_id);
    if (!next.get('technology')) next.set('technology', session.technology);
    navigate(`/investigation/sessions/${encodeURIComponent(session.session_id)}${queryString(next)}`);
  }

  function openCallFlow(session: Session) {
    const next = new URLSearchParams(params);
    next.delete('page');
    next.delete('search');
    next.set('dataset_id', session.dataset_id);
    next.set('session_id', session.session_id);
    if (!next.get('technology')) next.set('technology', session.technology);
    navigate(`/investigation/callflow/${encodeURIComponent(session.session_id)}${queryString(next)}`);
  }

  if (sessions.isLoading || datasets.isLoading || ues.isLoading || captureContext.isLoading)
    return <LoadingState />;
  const error = sessions.error || datasets.error || ues.error || captureContext.error;
  if (error)
    return (
      <ErrorState
        error={error as Error}
        retry={() => {
          void sessions.refetch();
          void datasets.refetch();
          void ues.refetch();
          void captureContext.refetch();
        }}
      />
    );

  // Honesty gate 1: capture → dataset resolution failed. Never fall back.
  if (captureId && captureContext.data?.resolution === 'DATASET_UNAVAILABLE') {
    const reason = captureContext.data.capture.error ?? captureContext.data.reason;
    return (
      <>
        <PageHeader
          eyebrow="Investigate"
          title="Sessions"
          desc="Dataset unavailable for the selected capture — OIRAN never substitutes another dataset."
        />
        <Card className="p-5 context-empty error flex items-start gap-3">
          <FileSearch width={18} height={18} className="text-bad shrink-0 mt-0.5" />
          <div>
            <h2 className="font-semibold">Dataset unavailable for this capture.</h2>
            <p className="text-sm2 text-mute mt-1">{reason}</p>
            <p className="text-sm2 text-mute">
              Recovery requires an authorised offline recovery operation; OIRAN will not
              substitute another dataset.
            </p>
            <Link
              className="inline-flex items-center gap-1.5 h-9 px-4 rounded-md text-md2 font-medium border border-line bg-surface hover:bg-canvas text-ink mt-3"
              to={`/operations/probes?search=${encodeURIComponent(captureId)}&capture_id=${encodeURIComponent(captureId)}`}
            >
              View Capture Details
            </Link>
          </div>
        </Card>
      </>
    );
  }

  const zeroSession = !!datasetId && rows.length === 0;

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
          aria-label="Dataset filter"
          value={datasetId || (datasetScope ? `scope:${datasetScope}` : '')}
          onChange={(e) => updateDataset(e.target.value)}
          className="h-9 px-3 rounded-md border border-line bg-surface text-md2 text-ink"
          data-testid="sessions-dataset-filter"
        >
          <option value="">All datasets</option>
          <option value="scope:HISTORICAL">Historical datasets</option>
          <option value="scope:CAPTURED_LIVE">Live captures</option>
          <option value="scope:RECOVERED">Recovered datasets</option>
          <option value="scope:DERIVED">Derived datasets</option>
          {(['HISTORICAL', 'CAPTURED_LIVE', 'RECOVERED', 'DERIVED'] as const).map((kind) => (
            <optgroup
              label={
                kind === 'CAPTURED_LIVE'
                  ? 'Live capture datasets'
                  : `${kind[0]}${kind.slice(1).toLowerCase()} datasets`
              }
              key={kind}
            >
              {datasets.data
                ?.filter((d) => d.dataset_kind === kind)
                .map((d) => (
                  <option key={d.dataset_id} value={d.dataset_id}>
                    {d.display_name} · {d.session_count} session{d.session_count === 1 ? '' : 's'}
                  </option>
                ))}
            </optgroup>
          ))}
        </select>
        <select
          aria-label="UE filter"
          value={ue}
          onChange={(e) => setParam('ue', e.target.value)}
          className="h-9 px-3 rounded-md border border-line bg-surface text-md2 text-ink"
        >
          <option value="">All UE contexts</option>
          {ues.data?.map((u) => (
            <option key={u.ue_context_id} value={u.ue_context_id}>
              {u.ue_pseudonym}
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

      {(captureId || datasetId || datasetScope) ? (
        <section
          className="flex flex-wrap items-center gap-4 text-sm2 text-mute border border-line rounded-xl bg-surface px-4 py-2.5"
          data-testid="sessions-context-strip"
        >
          <span className="inline-flex items-center gap-1.5">
            <FileSearch width={13} height={13} />
            <small className="text-mute">Capture</small>
            <b className="mono text-ink">{captureId || 'NOT SPECIFIED'}</b>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <ListTree width={13} height={13} />
            <small className="text-mute">Dataset</small>
            <b className="mono text-ink">
              {datasetId || `ALL ${datasetScope || 'DATASETS'}`}
            </b>
          </span>
          {probeId ? (
            <span className="inline-flex items-center gap-1.5">
              <small className="text-mute">Probe</small>
              <b className="mono text-ink">{probeId}</b>
            </span>
          ) : null}
          <span className="inline-flex items-center gap-1.5">
            <small className="text-mute">Sessions</small>
            <b className="mono text-ink">{sessions.data?.meta.total ?? 0}</b>
          </span>
        </section>
      ) : null}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px] items-start">
        <Card className="overflow-hidden">
          {zeroSession ? (
            <ZeroSessionBlock captureId={captureId} datasetId={datasetId} />
          ) : rows.length === 0 ? (
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
                      onClick={() => openSession(r)}
                      aria-selected={selected?.session_id === r.session_id}
                      data-testid={`session-row-${r.session_id}`}
                      className={`border-b border-line last:border-0 cursor-pointer ${
                        selected?.session_id === r.session_id
                          ? 'bg-brand-soft'
                          : 'hover:bg-canvas'
                      }`}
                    >
                      <td className="px-4 py-3 max-w-[260px] overflow-hidden">
                        {/* 2.4 fix: Procedure + mono session hash on a
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
                          <Link
                            to={`/investigation/callflow/${encodeURIComponent(r.session_id)}`}
                            className="hover:text-ink"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {r.session_id}
                          </Link>
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
            <span>{sessions.data?.meta.total ?? rows.length} sessions</span>
            <span>
              Page {sessions.data?.meta.page ?? 1} of{' '}
              {sessions.data?.meta.total_pages ?? 1}
            </span>
          </div>
          {rows.length > 0 && (sessions.data?.meta.total_pages ?? 1) > 1 ? (
            <div className="border-t border-line px-4 py-2">
              <Pagination
                page={sessions.data?.meta.page ?? 1}
                totalPages={sessions.data?.meta.total_pages ?? 1}
                onChange={(value) => {
                  setSessionPage(value);
                  const next = new URLSearchParams(params);
                  next.set('page', String(value));
                  setParams(next);
                }}
              />
            </div>
          ) : null}
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
          </Card>
        ) : null}
      </div>
    </>
  );
}

function ZeroSessionBlock({ captureId, datasetId }: { captureId: string; datasetId: string }) {
  const context = new URLSearchParams({ dataset_id: datasetId });
  if (captureId) context.set('capture_id', captureId);
  return (
    <div className="context-empty p-5 flex items-start gap-3" data-testid="sessions-zero-session">
      <ListTree width={18} height={18} className="shrink-0 mt-0.5 text-mute" />
      <div>
        <h2 className="font-semibold">
          {captureId
            ? 'No reconstructed sessions in this capture.'
            : 'No reconstructed sessions in this dataset.'}
        </h2>
        <p className="text-sm2 text-mute mt-1">
          The dataset remains available for packet and decoded-event inspection. OIRAN
          will not substitute a historical session.
        </p>
        <div className="flex flex-wrap gap-2 mt-3">
          <Link
            className="inline-flex items-center gap-1.5 h-9 px-4 rounded-md text-md2 font-medium bg-brand text-white shadow-e1 hover:brightness-110"
            to={`/analysis/packets?${context}&view=packets`}
          >
            View Packets
          </Link>
          <Link
            className="inline-flex items-center gap-1.5 h-9 px-4 rounded-md text-md2 font-medium border border-line bg-surface hover:bg-canvas text-ink"
            to={`/analysis/packets?${context}&view=decoded`}
          >
            View Decoded Events
          </Link>
          {captureId ? (
            <Link
              className="inline-flex items-center gap-1.5 h-9 px-4 rounded-md text-md2 font-medium border border-line bg-surface hover:bg-canvas text-ink"
              to={`/operations/probes?search=${encodeURIComponent(captureId)}&capture_id=${encodeURIComponent(captureId)}`}
            >
              View Capture Details
            </Link>
          ) : null}
        </div>
      </div>
    </div>
  );
}
