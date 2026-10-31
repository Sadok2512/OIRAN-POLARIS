import { Card, PageHeader, Pill, regTone } from '@/components/mockup';
import { EmptyState, ErrorState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import { useScenarioHistory } from '@/data/queries';

export function HistoryPage() {
  const history = useScenarioHistory();

  return (
    <>
      <PageHeader
        eyebrow="Review"
        title="History"
        desc="Terminal controller-owned jobs recorded by POLARIS."
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
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[620px] text-ep-md" data-testid="history-table">
              <thead>
                <tr className="text-left text-ep-xs uppercase tracking-wider text-mute border-b border-line">
                  <th className="px-4 py-2.5 font-semibold">Job</th>
                  <th className="px-3 py-2.5 font-semibold">Scenario</th>
                  <th className="px-3 py-2.5 font-semibold">UE</th>
                  <th className="px-3 py-2.5 font-semibold">Loops</th>
                  <th className="px-4 py-2.5 font-semibold">Result</th>
                </tr>
              </thead>
              <tbody>
                {history.data.items.map((item) => {
                  const result = (item.terminal_result ?? item.state).toUpperCase();
                  return (
                    <tr
                      key={item.job_id ?? item.scenario_id}
                      className="border-b border-line last:border-0"
                    >
                      <td className="px-4 py-3 mono text-ep-sm">{item.job_id ?? '—'}</td>
                      <td className="px-3 py-3">{item.scenario_id}</td>
                      <td className="px-3 py-3 mono">{item.target_ue_id ?? '—'}</td>
                      <td className="px-3 py-3 num">
                        {item.packets_sent ?? 0} / {item.packets_requested}
                      </td>
                      <td className="px-4 py-3">
                        <Pill tone={regTone(result)}>{result}</Pill>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </>
  );
}
