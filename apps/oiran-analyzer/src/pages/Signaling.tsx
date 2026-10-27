import { useEffect, useMemo, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { PageHeader } from '@/ui/PageHeader';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from '@/ui/EmptyErrorLoading';
import {
  useDatasets,
  useDatasetSessions,
  useSessionCallFlow,
} from '@/data/queries';
import { CallFlowLadder } from '@/components/CallFlowLadder';
import { EventInspector } from '@/components/EventInspector';
import type { CallFlowEvent } from '@shared/types';

export function SignalingPage() {
  const [params, setParams] = useSearchParams();
  const { sessionId: routeSessionId } = useParams<{ sessionId: string }>();
  const datasets = useDatasets();
  const [datasetId, setDatasetId] = useState<string | null>(
    params.get('dataset_id'),
  );
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    routeSessionId ?? params.get('session_id') ?? null,
  );
  const [event, setEvent] = useState<CallFlowEvent | null>(null);

  useEffect(() => {
    if (!datasetId && datasets.data && datasets.data.length > 0) {
      setDatasetId(datasets.data[0].dataset_id);
    }
  }, [datasets.data, datasetId]);

  const sessions = useDatasetSessions(datasetId);
  const callflow = useSessionCallFlow(selectedSessionId);

  const sessionOptions = useMemo(
    () =>
      (sessions.data ?? []).map((session) => ({
        value: session.session_id,
        label: `${session.ue_pseudonym || session.ue_context_id} · PDU ${session.pdu_session_id} · ${session.procedure}`,
      })),
    [sessions.data],
  );

  return (
    <>
      <PageHeader
        eyebrow="Investigation"
        title="Signaling"
        description="Message-by-message call flow across NGAP, NAS, SBI, PFCP and GTP-U. Timestamps and endpoints come from the backend decoded events — no fabricated direction."
        actions={
          <div className="flex items-center gap-2 text-ep-xs">
            <select
              className="ep-input text-ep-sm"
              value={datasetId ?? ''}
              onChange={(e) => {
                setDatasetId(e.target.value || null);
                setSelectedSessionId(null);
                setEvent(null);
                const next = new URLSearchParams(params);
                if (e.target.value) next.set('dataset_id', e.target.value);
                else next.delete('dataset_id');
                setParams(next, { replace: true });
              }}
              data-testid="signaling-dataset-select"
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
              onChange={(e) => {
                setSelectedSessionId(e.target.value || null);
                setEvent(null);
              }}
              disabled={!datasetId || sessionOptions.length === 0}
              data-testid="signaling-session-select"
            >
              <option value="">— Select session —</option>
              {sessionOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
        }
      />

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(320px,420px)]">
        <div className="min-w-0 flex flex-col gap-3">
          {!datasetId ? (
            <EmptyState title="No dataset selected" description="Pick a dataset to list sessions." />
          ) : !selectedSessionId ? (
            <EmptyState title="No session selected" description="Pick a session to view its call flow ladder." />
          ) : callflow.isLoading ? (
            <LoadingSkeleton label="Loading call flow" />
          ) : callflow.error ? (
            <ErrorState
              title="Could not load call flow"
              detail={(callflow.error as Error).message}
              onRetry={() => void callflow.refetch()}
            />
          ) : callflow.data ? (
            <CallFlowLadder
              callflow={callflow.data}
              onSelect={setEvent}
              highlightEventId={event?.event_id}
            />
          ) : null}
        </div>
        <EventInspector event={event} onClose={() => setEvent(null)} />
      </div>
    </>
  );
}
