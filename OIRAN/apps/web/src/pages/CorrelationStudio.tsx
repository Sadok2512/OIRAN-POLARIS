// 2.4.0 — Correlation page rebuilt to match docs/ui-mockups/oiran-analyzer.html.
// Mockup contract: 5-card confidence strip + 4-interface flow strip + 6-col
// edges table (Link / From → to / Matched on / Rule / Confidence / Limitations).
// Backed by /sessions/:id/callflow and /sessions/:id/correlations.

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useParams } from 'react-router-dom';
import { api } from '../services/api';
import type { CallFlow, CorrelationEdge, Session } from '../types/api';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';
import {
  Card,
  IfChip,
  PageHeader,
  Pill,
  confTone,
} from '../components/mockup';

type Correlations = { status: CallFlow['correlation_status']; edges: CorrelationEdge[] };

function pairLabel(a: string, b: string): string {
  const [left, right] = [a, b].sort((x, y) => (x === 'N2' ? -1 : y === 'N2' ? 1 : x.localeCompare(y)));
  return `${left} ↔ ${right}`;
}

export function CorrelationStudio() {
  const { sessionId } = useParams();

  const sessions = useQuery({
    queryKey: ['correlation-sessions'],
    queryFn: () =>
      api<Session[]>('/sessions?page_size=1&sort=start_timestamp&order=desc').then((x) => x.data),
    enabled: !sessionId,
  });
  const activeSession = sessionId ?? sessions.data?.[0]?.session_id ?? '';

  const flow = useQuery({
    queryKey: ['callflow', activeSession],
    queryFn: () => api<CallFlow>(`/sessions/${activeSession}/callflow`).then((x) => x.data),
    enabled: !!activeSession,
  });
  const correlations = useQuery({
    queryKey: ['session-correlations', activeSession],
    queryFn: () =>
      api<Correlations>(`/sessions/${activeSession}/correlations`).then((x) => x.data),
    enabled: !!activeSession,
  });

  const strip = useMemo(() => {
    const s = flow.data?.correlation_status;
    return [
      ['N2 ↔ SBI', s?.N2_SBI],
      ['SBI ↔ N4', s?.SBI_N4],
      ['N2 ↔ N4', s?.N2_N4],
      ['N4 ↔ N3', s?.N4_N3],
      ['End to end', s?.E2E],
    ] as const;
  }, [flow.data?.correlation_status]);

  if (!activeSession && sessions.isLoading) return <LoadingState />;
  if (!activeSession)
    return (
      <EmptyState title="No session selected">
        Open a session in the Sessions page to run the correlation studio.
      </EmptyState>
    );

  if (flow.isLoading || correlations.isLoading) return <LoadingState />;
  if (flow.error || correlations.error)
    return (
      <ErrorState
        error={(flow.error || correlations.error) as Error}
        retry={() => {
          void flow.refetch();
          void correlations.refetch();
        }}
      />
    );

  const edges = correlations.data?.edges ?? [];
  const interfaces: ('N2' | 'SBI' | 'N4' | 'N3')[] = ['N2', 'SBI', 'N4', 'N3'];
  const perInterface = (iface: string) =>
    flow.data?.events.filter((e) => e.interface === iface).length ?? 0;
  const linkConfidence = (a: string, b: string): string => {
    const edge = edges.find(
      (e) =>
        (e.source_interface === a && e.target_interface === b) ||
        (e.source_interface === b && e.target_interface === a),
    );
    return edge?.confidence ?? 'UNKNOWN';
  };

  return (
    <>
      <PageHeader
        eyebrow={`Investigate · ${activeSession}`}
        title="Correlation"
        desc="How the N2, SBI, N4 and N3 legs of one session are tied together, with the rule and identifiers behind each link."
      />
      <div className="grid gap-3 grid-cols-2 lg:grid-cols-5">
        {strip.map(([label, c]) => (
          <Card key={label} className="p-4 flex flex-col gap-2" data-testid={`corr-card-${label}`}>
            <p className="text-xs2 font-semibold uppercase tracking-wider text-mute">{label}</p>
            <span className="self-start">
              <Pill tone={confTone(c)}>{c ?? 'UNKNOWN'}</Pill>
            </span>
          </Card>
        ))}
      </div>
      <Card className="p-5 overflow-x-auto">
        <div className="min-w-[640px] flex items-center justify-between gap-2">
          {interfaces.map((i, k, arr) => (
            <div key={i} className="contents">
              <div className="flex-1 rounded-xl border border-line p-3 text-center">
                <IfChip i={i} />
                <p className="mt-1.5 text-sm2 text-mute">
                  {perInterface(i)} event{perInterface(i) > 1 ? 's' : ''}
                </p>
              </div>
              {k < arr.length - 1 ? (
                <div className="flex flex-col items-center gap-1 w-28">
                  <Pill tone={confTone(linkConfidence(i, arr[k + 1]))}>
                    {linkConfidence(i, arr[k + 1])}
                  </Pill>
                  <div className="h-0.5 w-full bg-line" />
                </div>
              ) : null}
            </div>
          ))}
        </div>
      </Card>
      <Card className="overflow-hidden" data-testid="correlation-edges">
        {edges.length === 0 ? (
          <p className="px-5 py-6 text-sm2 text-mute">No correlation edge reported for this session.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-md2">
              <thead>
                <tr className="text-left text-xs2 uppercase tracking-wider text-mute border-b border-line">
                  <th className="px-4 py-2.5 font-semibold">Link</th>
                  <th className="px-3 py-2.5 font-semibold">From → to</th>
                  <th className="px-3 py-2.5 font-semibold">Matched on</th>
                  <th className="px-3 py-2.5 font-semibold">Rule</th>
                  <th className="px-3 py-2.5 font-semibold">Confidence</th>
                  <th className="px-3 py-2.5 font-semibold">Limitations</th>
                </tr>
              </thead>
              <tbody>
                {edges.map((x) => (
                  <tr key={x.edge_id} className="border-b border-line last:border-0">
                    <td className="px-4 py-3 font-medium whitespace-nowrap">
                      {pairLabel(x.source_interface, x.target_interface)}
                    </td>
                    <td className="px-3 py-3 mono text-sm2 whitespace-nowrap">
                      <span title={x.source_event_id}>{x.source_event_id}</span>
                      <span className="text-mute"> → </span>
                      <span title={x.target_event_id}>{x.target_event_id}</span>
                    </td>
                    <td
                      className="px-3 py-3 text-sm2 max-w-[260px] truncate"
                      title={x.matching_identifiers.join(', ')}
                    >
                      {x.matching_identifiers.join(', ')}
                    </td>
                    <td className="px-3 py-3 mono text-xs2 whitespace-nowrap">
                      {x.rule_id} v{x.rule_version}
                    </td>
                    <td className="px-3 py-3">
                      <Pill tone={confTone(x.confidence)}>{x.confidence}</Pill>
                    </td>
                    <td className="px-3 py-3 text-sm2 text-mute">
                      {x.limitations?.length ? x.limitations.join(' · ') : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <p className="text-sm2 text-mute">
        Confidence is the engine's verdict per rule. Exact = identical tunnel or
        context identifier on both sides; Possible = consistent but not unique
        in this capture window.
      </p>
    </>
  );
}
