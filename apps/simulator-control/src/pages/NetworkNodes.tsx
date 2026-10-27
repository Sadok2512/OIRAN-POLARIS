import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { EmptyState, ErrorState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import { useAuth, useNodes } from '@/data/queries';

export function NetworkNodesPage() {
  const auth = useAuth();
  const nodes = useNodes();
  const canOperate = auth.data?.can_start === true;

  return (
    <>
      <PageHeader
        eyebrow="Operations"
        title="Network Nodes"
        description="gNB / eNB inventory reported by POLARIS /nodes. Start/Stop remain backend-authorized and are disabled when the controller does not own the node."
        actions={
          <StatusIndicator
            state={canOperate ? 'OPERATOR_READY' : 'VIEWER_READONLY'}
            tone={canOperate ? 'success' : 'warning'}
            label={canOperate ? 'Operator role active' : 'Viewer — read-only'}
          />
        }
      />

      {nodes.isLoading && !nodes.data && <LoadingSkeleton label="Loading nodes" />}
      {nodes.error && (
        <ErrorState
          title="Could not load nodes"
          detail={(nodes.error as Error).message}
          onRetry={() => void nodes.refetch()}
        />
      )}
      {nodes.data && nodes.data.items.length === 0 && (
        <EmptyState
          title="No node configured"
          description="POLARIS has not reported any gNB/eNB."
        />
      )}
      {nodes.data && nodes.data.items.length > 0 && (
        <div className="ep-card overflow-hidden">
          <table className="ep-table" data-testid="nodes-table">
            <thead>
              <tr>
                <th>Node</th>
                <th>Technology</th>
                <th>PLMN</th>
                <th>Cell ID</th>
                <th>N2</th>
                <th>N3</th>
                <th>Process</th>
                <th>Health</th>
                <th>Ownership</th>
              </tr>
            </thead>
            <tbody>
              {nodes.data.items.map((node) => (
                <tr key={node.id} data-testid={`node-row-${node.id}`}>
                  <td>
                    <div className="flex flex-col">
                      <span className="font-medium">{node.id}</span>
                      <span className="text-text-secondary text-ep-xs truncate">{node.name}</span>
                    </div>
                  </td>
                  <td>
                    {node.technology}
                    <div className="text-text-secondary text-ep-xs">{node.simulator}</div>
                  </td>
                  <td className="mono text-ep-xs">{node.plmn}</td>
                  <td className="mono text-ep-xs">{node.cell_id}</td>
                  <td className="mono text-ep-xs">{node.n2_endpoint ?? '—'}</td>
                  <td className="mono text-ep-xs">{node.n3_endpoint ?? '—'}</td>
                  <td><StatusIndicator state={node.process_state} compact /></td>
                  <td>{node.health}</td>
                  <td>
                    {node.controller_owned ? (
                      <span className="ep-badge border-primary/40 text-primary">controller</span>
                    ) : (
                      <span className="ep-badge border-warning/40 text-warning">shared · protected</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="px-3 py-2 text-ep-xs text-text-secondary border-t border-border">
            Node Start / Stop will appear once the backend exposes a non-shared, controller-authorized endpoint for the
            observed nodes. Current nodes are managed by the certified POLARIS lab controller.
          </p>
        </div>
      )}
    </>
  );
}
