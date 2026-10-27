import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { PageHeader } from '@/ui/PageHeader';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
  Unavailable,
} from '@/ui/EmptyErrorLoading';
import {
  useDatasets,
  useDatasetSessions,
  useSessionCallFlow,
  useUes,
} from '@/data/queries';
import { buildHierarchy } from '@/analyzer/hierarchy';
import { count } from '@/data/format';

export function UserPlanePage() {
  const [params, setParams] = useSearchParams();
  const datasets = useDatasets();
  const ues = useUes();
  const [datasetId, setDatasetId] = useState<string | null>(
    params.get('dataset_id'),
  );
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    params.get('session_id') ?? null,
  );

  useEffect(() => {
    if (!datasetId && datasets.data && datasets.data.length > 0) {
      setDatasetId(datasets.data[0].dataset_id);
    }
  }, [datasets.data, datasetId]);

  const sessions = useDatasetSessions(datasetId);
  const callflow = useSessionCallFlow(selectedSessionId);

  const hierarchy = useMemo(() => {
    if (!ues.data || !sessions.data) return [];
    return buildHierarchy(ues.data, sessions.data);
  }, [ues.data, sessions.data]);

  // Pre-select first session for convenience.
  useEffect(() => {
    if (!selectedSessionId && hierarchy[0]?.pduSessions[0]) {
      setSelectedSessionId(hierarchy[0].pduSessions[0].session.session_id);
    }
  }, [hierarchy, selectedSessionId]);

  const selectedPdu = useMemo(() => {
    if (!selectedSessionId) return undefined;
    for (const ue of hierarchy) {
      const node = ue.pduSessions.find(
        (p) => p.session.session_id === selectedSessionId,
      );
      if (node) return node;
    }
    return undefined;
  }, [hierarchy, selectedSessionId]);

  const n3Events = useMemo(
    () =>
      (callflow.data?.events ?? []).filter((event) =>
        /N3|GTP|USERPLANE/i.test(event.interface),
      ),
    [callflow.data],
  );

  return (
    <>
      <PageHeader
        eyebrow="Investigation"
        title="User Plane"
        description="GTP-U tunnels, QoS flows and encapsulated IP traffic for a selected PDU session. Only backend-reported counters are shown — packet loss claims are left unavailable because capture drops ≠ path loss."
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
              {hierarchy.flatMap((ue) =>
                ue.pduSessions.map((pdu) => (
                  <option
                    key={pdu.session.session_id}
                    value={pdu.session.session_id}
                  >
                    {ue.context.ue_pseudonym} · PDU {pdu.pduSessionId}
                  </option>
                )),
              )}
            </select>
          </div>
        }
      />

      {!datasetId ? (
        <EmptyState title="No dataset selected" description="Pick a dataset to list user-plane traffic." />
      ) : sessions.isLoading ? (
        <LoadingSkeleton label="Loading sessions" />
      ) : sessions.error ? (
        <ErrorState
          title="Could not load sessions"
          detail={(sessions.error as Error).message}
          onRetry={() => void sessions.refetch()}
        />
      ) : !selectedSessionId || !selectedPdu ? (
        <EmptyState
          title="Pick a PDU session"
          description="Choose a session to show its tunnels and flows."
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <section className="ep-card p-4">
            <h2 className="text-ep-md font-semibold mb-2">
              GTP-U tunnels · PDU {selectedPdu.pduSessionId}
            </h2>
            {selectedPdu.gtpuTeids.length === 0 ? (
              <Unavailable reason="Backend decoded tree did not expose any TEID for this session." />
            ) : (
              <ul className="flex flex-wrap gap-1">
                {selectedPdu.gtpuTeids.map((teid) => (
                  <li key={teid}>
                    <span className="ep-badge mono">TEID {teid}</span>
                  </li>
                ))}
              </ul>
            )}
            <h3 className="text-ep-sm font-semibold mt-4 mb-1">PFCP SEIDs</h3>
            {selectedPdu.pfcpSeids.length === 0 ? (
              <Unavailable reason="Backend did not expose PFCP SEIDs for this session." />
            ) : (
              <ul className="flex flex-wrap gap-1">
                {selectedPdu.pfcpSeids.map((seid) => (
                  <li key={seid}>
                    <span className="ep-badge mono">SEID {seid}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="ep-card p-4">
            <h2 className="text-ep-md font-semibold mb-2">
              Encapsulated flows · {count(selectedPdu.flows.length)}
            </h2>
            {selectedPdu.flows.length === 0 ? (
              <Unavailable reason="No N3 / GTP-U encapsulated flow has been reported for this session." />
            ) : (
              <table className="ep-table text-ep-xs">
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th className="text-right">Packets</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedPdu.flows.map((flow, index) => (
                    <tr key={`${flow.source}-${flow.destination}-${index}`}>
                      <td><span className="ep-badge mono">{flow.protocol}</span></td>
                      <td className="mono">{flow.source}</td>
                      <td className="mono">{flow.destination}</td>
                      <td className="num text-right">{count(flow.packetCount)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <section className="ep-card p-4 lg:col-span-2">
            <h2 className="text-ep-md font-semibold mb-2">
              N3 events · {count(n3Events.length)}
            </h2>
            {callflow.isLoading ? (
              <LoadingSkeleton label="Loading call flow" />
            ) : callflow.error ? (
              <ErrorState
                title="Call flow unavailable"
                detail={(callflow.error as Error).message}
              />
            ) : n3Events.length === 0 ? (
              <Unavailable reason="Backend returned no N3 event for this session (no live user-plane traffic captured)." />
            ) : (
              <table className="ep-table text-ep-xs">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Message</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Direction</th>
                  </tr>
                </thead>
                <tbody>
                  {n3Events.slice(0, 100).map((event) => (
                    <tr key={event.event_id}>
                      <td className="mono text-ep-xs">{event.timestamp}</td>
                      <td>{event.message_name}</td>
                      <td className="mono">{event.source_participant}</td>
                      <td className="mono">{event.destination_participant}</td>
                      <td>{event.direction}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <p className="text-ep-xs text-text-secondary mt-2">
              Throughput over time, UL/DL direction and end-to-end packet loss
              require a dedicated backend contract (e.g. per-TEID counters);
              the UI will render those as soon as the contract exists.
            </p>
          </section>
        </div>
      )}
    </>
  );
}
