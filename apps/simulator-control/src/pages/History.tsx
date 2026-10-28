import { PageHeader } from '@/ui/PageHeader';
import { EmptyState, ErrorState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { useScenarioHistory } from '@/data/queries';
import { count, isoToLocal } from '@/data/format';

export function HistoryPage() {
  const history = useScenarioHistory();

  return (
    <>
      <PageHeader
        eyebrow="Review"
        title="Scenario history"
        description="Terminal controller-owned jobs recorded by POLARIS. Live and controller-ignored jobs are not included — see /scenarios/history."
      />
      {history.isLoading && !history.data && <LoadingSkeleton label="Loading history" />}
      {history.error && (
        <ErrorState
          title="Could not load history"
          detail={(history.error as Error).message}
          onRetry={() => void history.refetch()}
        />
      )}
      {history.data && history.data.items.length === 0 && (
        <EmptyState
          title="No terminal job"
          description="Completed or failed scenarios will appear here once POLARIS records them."
        />
      )}
      {history.data && history.data.items.length > 0 && (
        <div className="ep-card overflow-hidden">
          <table className="ep-table" data-testid="history-table">
            <thead>
              <tr>
                <th>Scenario ID</th>
                <th>Target UE</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Packets</th>
                <th>Terminal result</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {history.data.items.map((item) => (
                <tr key={item.scenario_id}>
                  <td className="mono text-ep-xs">{item.scenario_id}</td>
                  <td>{item.target_ue_id ?? '—'}</td>
                  <td>{isoToLocal(item.started_at)}</td>
                  <td className="num">{item.duration_seconds}s</td>
                  <td className="num">
                    {count(item.packets_sent)} / {count(item.packets_requested)}
                  </td>
                  <td>{item.terminal_result ?? '—'}</td>
                  <td><StatusIndicator state={item.state} compact /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
