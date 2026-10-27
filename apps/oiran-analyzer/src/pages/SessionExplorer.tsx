import { useEffect, useMemo, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { PanelGroup, Panel, PanelResizeHandle } from 'react-resizable-panels';
import { Search } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
  Unavailable,
} from '@/ui/EmptyErrorLoading';
import { EvidenceBadge } from '@/ui/EvidenceBadge';
import {
  useDatasets,
  useDatasetSessions,
  useSession,
  useSessionCallFlow,
  useUes,
} from '@/data/queries';
import { buildHierarchy, buildUnknownBucket } from '@/analyzer/hierarchy';
import { UeTree } from '@/components/UeTree';
import { SessionSummary } from '@/components/SessionSummary';
import { EventInspector } from '@/components/EventInspector';
import { CallFlowLadder } from '@/components/CallFlowLadder';
import type { CallFlowEvent } from '@shared/types';

export function SessionExplorerPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { sessionId: routeSessionId } = useParams<{ sessionId: string }>();

  const datasets = useDatasets();
  const ues = useUes();

  const paramDatasetId = searchParams.get('dataset_id');
  const [datasetId, setDatasetId] = useState<string | null>(paramDatasetId);
  const [search, setSearch] = useState('');
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    routeSessionId ?? searchParams.get('session_id') ?? null,
  );
  const [selectedEvent, setSelectedEvent] = useState<CallFlowEvent | null>(
    null,
  );

  // Default to first dataset reported by the backend (when none in URL).
  useEffect(() => {
    if (!datasetId && datasets.data && datasets.data.length > 0) {
      setDatasetId(datasets.data[0].dataset_id);
    }
  }, [datasets.data, datasetId]);

  const sessions = useDatasetSessions(datasetId);
  const session = useSession(selectedSessionId);
  const callflow = useSessionCallFlow(selectedSessionId);

  const hierarchy = useMemo(() => {
    if (!ues.data || !sessions.data) return [];
    return buildHierarchy(ues.data, sessions.data);
  }, [ues.data, sessions.data]);

  const unknownPdus = useMemo(() => {
    if (!ues.data || !sessions.data) return [];
    return buildUnknownBucket(ues.data, sessions.data);
  }, [ues.data, sessions.data]);

  // When a session is selected, surface its PDU/UE hierarchy node to
  // show the right-side resource lists (PFCP/GTP-U/flows).
  const selectedPdu = useMemo(() => {
    if (!selectedSessionId) return undefined;
    for (const ue of hierarchy) {
      const node = ue.pduSessions.find(
        (p) => p.session.session_id === selectedSessionId,
      );
      if (node) return node;
    }
    return unknownPdus.find((p) => p.session.session_id === selectedSessionId);
  }, [hierarchy, unknownPdus, selectedSessionId]);

  return (
    <>
      <PageHeader
        eyebrow="Investigation"
        title="Session Explorer"
        description="Hierarchical UE → PDU Session → PFCP / GTP-U / flows reconstructed from the OIRAN session engine. Multi-UE and multi-PDU isolation preserved. Missing fields render as “—”."
        actions={
          <div className="flex items-center gap-2 text-ep-xs">
            <label htmlFor="dataset-select" className="text-text-secondary">
              Dataset
            </label>
            <select
              id="dataset-select"
              className="ep-input text-ep-sm"
              value={datasetId ?? ''}
              onChange={(event) => {
                setDatasetId(event.target.value || null);
                setSelectedSessionId(null);
                setSelectedEvent(null);
                const next = new URLSearchParams(searchParams);
                if (event.target.value) {
                  next.set('dataset_id', event.target.value);
                } else {
                  next.delete('dataset_id');
                }
                setSearchParams(next, { replace: true });
              }}
              data-testid="dataset-select"
            >
              <option value="">— Select dataset —</option>
              {datasets.data?.map((ds) => (
                <option key={ds.dataset_id} value={ds.dataset_id}>
                  {ds.display_name} ({ds.dataset_kind})
                </option>
              ))}
            </select>
          </div>
        }
      />

      {ues.isLoading || datasets.isLoading ? (
        <LoadingSkeleton label="Loading UE + dataset inventory" />
      ) : ues.error ? (
        <ErrorState
          title="Could not load UE inventory"
          detail={(ues.error as Error).message}
          onRetry={() => void ues.refetch()}
        />
      ) : datasets.error ? (
        <ErrorState
          title="Could not load datasets"
          detail={(datasets.error as Error).message}
          onRetry={() => void datasets.refetch()}
        />
      ) : !datasetId ? (
        <EmptyState
          title="No dataset selected"
          description="Pick a dataset above to populate the UE hierarchy."
        />
      ) : (
        <div className="h-[calc(100vh-180px)] min-h-[520px]" data-testid="session-explorer">
          <PanelGroup direction="horizontal" autoSaveId="analyzer-session-explorer">
            <Panel defaultSize={22} minSize={16} className="flex flex-col">
              <section className="ep-card flex-1 min-h-0 flex flex-col p-3">
                <header className="flex items-center gap-2 mb-2">
                  <label className="relative flex-1">
                    <Search
                      className="absolute left-2 top-1/2 -translate-y-1/2 text-text-secondary"
                      width={13}
                      height={13}
                      aria-hidden="true"
                    />
                    <input
                      className="ep-input pl-7 w-full"
                      placeholder="Search UE, PDU, SEID, TEID"
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                      aria-label="Search hierarchy"
                      data-testid="hierarchy-search"
                    />
                  </label>
                </header>
                <div className="flex-1 overflow-y-auto">
                  {sessions.isLoading ? (
                    <LoadingSkeleton label="Loading sessions" />
                  ) : sessions.error ? (
                    <ErrorState
                      title="Could not load dataset sessions"
                      detail={(sessions.error as Error).message}
                      onRetry={() => void sessions.refetch()}
                    />
                  ) : hierarchy.length === 0 && unknownPdus.length === 0 ? (
                    <EmptyState
                      title="No sessions"
                      description="This dataset has no session reconstructed by the backend yet."
                    />
                  ) : (
                    <UeTree
                      hierarchy={hierarchy}
                      unknownPdus={unknownPdus}
                      selection={
                        selectedSessionId
                          ? { kind: 'session', sessionId: selectedSessionId }
                          : null
                      }
                      onSelect={(sel) => {
                        setSelectedSessionId(sel?.sessionId ?? null);
                        setSelectedEvent(null);
                      }}
                      search={search}
                    />
                  )}
                </div>
              </section>
            </Panel>
            <PanelResizeHandle className="w-1 bg-border hover:bg-primary/40" />
            <Panel defaultSize={48} minSize={28} className="flex flex-col gap-3 min-h-0">
              {!selectedSessionId ? (
                <EmptyState
                  title="Pick a PDU session"
                  description="Select a PDU Session in the hierarchy to inspect its summary, call flow and correlation evidence."
                />
              ) : session.isLoading ? (
                <LoadingSkeleton label="Loading session summary" />
              ) : session.error ? (
                <ErrorState
                  title="Could not load session"
                  detail={(session.error as Error).message}
                  onRetry={() => void session.refetch()}
                />
              ) : (
                session.data && (
                  <>
                    <SessionSummary session={session.data} pdu={selectedPdu} />
                    {callflow.isLoading ? (
                      <LoadingSkeleton label="Loading call flow" />
                    ) : callflow.error ? (
                      <Unavailable reason="Call flow is not available for this session (backend did not return it)." />
                    ) : callflow.data ? (
                      <>
                        <CorrelationBanner callflow={callflow.data} />
                        <CallFlowLadder
                          callflow={callflow.data}
                          onSelect={setSelectedEvent}
                          highlightEventId={selectedEvent?.event_id}
                        />
                      </>
                    ) : null}
                  </>
                )
              )}
            </Panel>
            <PanelResizeHandle className="w-1 bg-border hover:bg-primary/40" />
            <Panel defaultSize={30} minSize={20} className="flex flex-col min-h-0">
              <div className="flex-1 overflow-y-auto">
                <EventInspector
                  event={selectedEvent}
                  onClose={() => setSelectedEvent(null)}
                />
              </div>
            </Panel>
          </PanelGroup>
        </div>
      )}
    </>
  );
}

function CorrelationBanner({ callflow }: { callflow: Parameters<typeof CallFlowLadder>[0]['callflow'] }) {
  const entries: Array<[string, keyof typeof callflow.correlation_status]> = [
    ['N2 ↔ N4', 'N2_N4'],
    ['N2 ↔ SBI', 'N2_SBI'],
    ['SBI ↔ N4', 'SBI_N4'],
    ['N4 ↔ N3', 'N4_N3'],
    ['E2E', 'E2E'],
  ];
  return (
    <section
      className="ep-card p-3 flex flex-wrap items-center gap-3 text-ep-xs"
      data-testid="correlation-banner"
    >
      <span className="font-semibold text-text-secondary uppercase tracking-wider">
        Correlation
      </span>
      {entries.map(([label, key]) => {
        const value = callflow.correlation_status[key];
        if (!value) return null;
        return (
          <span key={label} className="inline-flex items-center gap-1">
            <span className="text-text-secondary">{label}</span>
            <EvidenceBadge confidence={value} compact />
          </span>
        );
      })}
    </section>
  );
}
