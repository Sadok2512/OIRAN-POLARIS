import { Database, Users, Share2, FileSearch } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from '@/ui/EmptyErrorLoading';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { useDatasets, useMetrics, useUes, useVersion } from '@/data/queries';
import { count } from '@/data/format';

function MetricTile({
  label,
  value,
  sub,
  Icon,
}: {
  label: string;
  value: string;
  sub?: string;
  Icon?: typeof Database;
}) {
  return (
    <article className="ep-card p-4 flex flex-col gap-1" data-testid="metric-tile">
      <header className="flex items-center justify-between">
        <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
          {label}
        </span>
        {Icon && <Icon width={14} height={14} className="text-text-secondary" />}
      </header>
      <strong className="text-ep-xl num text-text-primary">{value}</strong>
      {sub && <span className="text-ep-xs text-text-secondary">{sub}</span>}
    </article>
  );
}

export function OverviewPage() {
  const datasets = useDatasets();
  const ues = useUes();
  const metrics = useMetrics();
  const version = useVersion();

  const anyLoading = datasets.isLoading || ues.isLoading;
  const anyError = datasets.error || ues.error;

  return (
    <>
      <PageHeader
        eyebrow="Analysis"
        title="OIRAN Analyzer"
        description="Analyze historical and live OIRAN datasets. Hierarchical UE / PDU session reconstruction, signaling call flows, correlation evidence, and packet provenance."
        actions={
          <StatusIndicator
            state={metrics.data?.mode ?? 'UNKNOWN'}
            label={metrics.data?.mode ? `Mode: ${metrics.data.mode}` : 'Mode unknown'}
          />
        }
      />

      {anyLoading && !datasets.data && <LoadingSkeleton label="Loading inventory" />}
      {anyError && !anyLoading && (
        <ErrorState
          title="Could not load analyzer inventory"
          detail={(anyError as Error).message}
          onRetry={() => {
            void datasets.refetch();
            void ues.refetch();
          }}
        />
      )}

      {!anyLoading && !anyError && (
        <>
          <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
            <MetricTile
              label="Datasets"
              value={count(datasets.data?.length)}
              sub={
                datasets.data?.filter((d) => d.dataset_kind === 'CAPTURED_LIVE')
                  .length
                  ? `${datasets.data.filter((d) => d.dataset_kind === 'CAPTURED_LIVE').length} captured live`
                  : 'None captured live'
              }
              Icon={Database}
            />
            <MetricTile
              label="UE contexts"
              value={count(ues.data?.length)}
              Icon={Users}
            />
            <MetricTile
              label="Sessions"
              value={count(
                datasets.data?.reduce(
                  (sum, dataset) => sum + (dataset.session_count ?? 0),
                  0,
                ),
              )}
              Icon={Share2}
            />
            <MetricTile
              label="Events"
              value={count(
                datasets.data?.reduce(
                  (sum, dataset) => sum + (dataset.event_count ?? 0),
                  0,
                ),
              )}
              Icon={FileSearch}
            />
          </div>

          <section className="mt-6 ep-card p-5">
            <h2 className="text-ep-md font-semibold mb-3">Decoder versions</h2>
            {version.data?.decoders ? (
              <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-5 gap-y-1 text-ep-sm">
                {Object.entries(version.data.decoders).map(([name, value]) => (
                  <div key={name} className="contents">
                    <dt className="text-text-secondary">{name}</dt>
                    <dd className="mono text-ep-xs">{value}</dd>
                  </div>
                ))}
              </dl>
            ) : (
              <EmptyState
                title="Decoder versions unavailable"
                description="Backend did not report decoder versions."
              />
            )}
          </section>
        </>
      )}
    </>
  );
}
