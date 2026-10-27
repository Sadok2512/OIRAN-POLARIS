import { useEffect, useMemo, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  type Edge,
  type Node,
} from '@xyflow/react';
import { PageHeader } from '@/ui/PageHeader';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from '@/ui/EmptyErrorLoading';
import { EvidenceBadge, EVIDENCE_DESCRIPTION } from '@/ui/EvidenceBadge';
import {
  useDatasets,
  useDatasetSessions,
  useSessionCallFlow,
  useSessionCorrelations,
} from '@/data/queries';
import type { Confidence } from '@shared/types';

const CONFIDENCE_COLOR: Record<Confidence, string> = {
  EXACT: '#059669',
  STRONG: '#2563EB',
  POSSIBLE: '#D97706',
  UNKNOWN: '#94A3B8',
};

export function CorrelationStudioPage() {
  const [params, setParams] = useSearchParams();
  const { sessionId: routeSessionId } = useParams<{ sessionId: string }>();
  const datasets = useDatasets();
  const [datasetId, setDatasetId] = useState<string | null>(
    params.get('dataset_id'),
  );
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    routeSessionId ?? params.get('session_id') ?? null,
  );

  useEffect(() => {
    if (!datasetId && datasets.data && datasets.data.length > 0) {
      setDatasetId(datasets.data[0].dataset_id);
    }
  }, [datasets.data, datasetId]);

  const sessions = useDatasetSessions(datasetId);
  const callflow = useSessionCallFlow(selectedSessionId);
  const correlations = useSessionCorrelations(selectedSessionId);

  const graph = useMemo(() => {
    if (!callflow.data || !correlations.data) return { nodes: [], edges: [] };
    const nodes: Node[] = callflow.data.events.map((event, index) => ({
      id: event.event_id,
      position: {
        x: 60 + (index % 6) * 220,
        y: 60 + Math.floor(index / 6) * 140,
      },
      data: {
        label: `${event.message_name}\n${event.interface}`,
      },
      style: {
        width: 180,
        fontSize: 11,
        padding: 8,
        borderRadius: 8,
        border: '1px solid var(--c-border)',
        background: 'var(--c-surface)',
        color: 'var(--c-text-primary)',
        whiteSpace: 'pre-wrap',
      },
    }));
    const edges: Edge[] = correlations.data.map((edge) => ({
      id: edge.edge_id,
      source: edge.source_event_id,
      target: edge.target_event_id,
      label: edge.confidence,
      type: 'smoothstep',
      animated: edge.confidence === 'EXACT',
      style: {
        stroke: CONFIDENCE_COLOR[edge.confidence],
        strokeWidth: edge.confidence === 'EXACT' ? 2 : 1,
      },
      labelStyle: {
        fontSize: 10,
        fill: CONFIDENCE_COLOR[edge.confidence],
      },
    }));
    return { nodes, edges };
  }, [callflow.data, correlations.data]);

  return (
    <>
      <PageHeader
        eyebrow="Investigation"
        title="Correlation Studio"
        description="Visualize correlation edges emitted by the OIRAN correlation engine. Edge thickness and color reflect backend-reported confidence. No edge is promoted beyond its backend confidence."
        actions={
          <div className="flex items-center gap-2 text-ep-xs">
            <select
              className="ep-input text-ep-sm"
              value={datasetId ?? ''}
              onChange={(e) => {
                setDatasetId(e.target.value || null);
                setSelectedSessionId(null);
                const next = new URLSearchParams(params);
                if (e.target.value) next.set('dataset_id', e.target.value);
                else next.delete('dataset_id');
                setParams(next, { replace: true });
              }}
            >
              <option value="">— Select dataset —</option>
              {datasets.data?.map((ds) => (
                <option key={ds.dataset_id} value={ds.dataset_id}>
                  {ds.display_name}
                </option>
              ))}
            </select>
            <select
              className="ep-input text-ep-sm"
              value={selectedSessionId ?? ''}
              onChange={(e) => setSelectedSessionId(e.target.value || null)}
              disabled={!datasetId}
            >
              <option value="">— Select session —</option>
              {sessions.data?.map((session) => (
                <option key={session.session_id} value={session.session_id}>
                  {session.ue_pseudonym} · PDU {session.pdu_session_id}
                </option>
              ))}
            </select>
          </div>
        }
      />

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_240px] h-[calc(100vh-200px)] min-h-[480px]">
        <section
          className="ep-card overflow-hidden"
          data-testid="correlation-graph"
        >
          {!selectedSessionId ? (
            <EmptyState
              title="No session selected"
              description="Pick a session to render its correlation graph."
            />
          ) : callflow.isLoading || correlations.isLoading ? (
            <LoadingSkeleton label="Loading correlation evidence" />
          ) : callflow.error || correlations.error ? (
            <ErrorState
              title="Could not load correlation evidence"
              detail={
                ((callflow.error ?? correlations.error) as Error | undefined)
                  ?.message
              }
            />
          ) : graph.nodes.length === 0 ? (
            <EmptyState
              title="No events"
              description="The backend returned no events for this session."
            />
          ) : (
            <ReactFlowProvider>
              <ReactFlow
                nodes={graph.nodes}
                edges={graph.edges}
                fitView
                proOptions={{ hideAttribution: true }}
              >
                <Background gap={16} />
                <Controls showInteractive={false} position="bottom-left" />
                <MiniMap pannable zoomable position="bottom-right" />
              </ReactFlow>
            </ReactFlowProvider>
          )}
        </section>
        <aside className="ep-card p-4 text-ep-sm" aria-label="Correlation legend">
          <h3 className="text-ep-sm font-semibold mb-2">Evidence legend</h3>
          <ul className="flex flex-col gap-2">
            {(['EXACT', 'STRONG', 'POSSIBLE', 'UNKNOWN'] as Confidence[]).map(
              (level) => (
                <li key={level} className="flex items-start gap-2">
                  <EvidenceBadge confidence={level} />
                  <p className="text-ep-xs text-text-secondary flex-1">
                    {EVIDENCE_DESCRIPTION[level]}
                  </p>
                </li>
              ),
            )}
          </ul>
          {correlations.data && (
            <>
              <h4 className="text-ep-sm font-semibold mt-4 mb-1">
                Edges in this session
              </h4>
              <dl className="grid grid-cols-2 text-ep-xs gap-y-1">
                {(['EXACT', 'STRONG', 'POSSIBLE', 'UNKNOWN'] as Confidence[]).map(
                  (level) => (
                    <div key={level} className="contents">
                      <dt className="text-text-secondary">{level}</dt>
                      <dd className="num text-right">
                        {
                          correlations.data.filter(
                            (edge) => edge.confidence === level,
                          ).length
                        }
                      </dd>
                    </div>
                  ),
                )}
              </dl>
            </>
          )}
        </aside>
      </div>
    </>
  );
}
