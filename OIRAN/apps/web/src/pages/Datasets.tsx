// 2.4.0 (new) — Datasets page. Mockup lists live / historical / recovered
// captures as read-only data sources. Each card shows the kind pill,
// Sessions / Events / Packets numbers, ingestion status, accounting and
// the pinned decoder versions.

import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import { api } from '../services/api';
import type { Dataset } from '../types/api';
import { ErrorState, LoadingState, EmptyState } from '../components/AsyncState';
import { Card, PageHeader, Pill, kindTone } from '../components/mockup';

export function Datasets() {
  const datasets = useQuery({
    queryKey: ['datasets-page'],
    queryFn: () => api<Dataset[]>('/datasets?page_size=100').then((x) => x.data),
  });

  if (datasets.isLoading) return <LoadingState />;
  if (datasets.error)
    return (
      <ErrorState
        error={datasets.error as Error}
        retry={() => void datasets.refetch()}
      />
    );
  const rows = datasets.data ?? [];

  return (
    <>
      <PageHeader
        eyebrow="Evidence"
        title="Datasets"
        desc="What the analyzer reads from: live captures from Probe Manager, imported files and recovered checkpoints. All read-only."
      />
      {rows.length === 0 ? (
        <EmptyState title="No dataset reported by /datasets." />
      ) : (
        <div className="grid gap-5 lg:grid-cols-3">
          {rows.map((d) => (
            <Card
              key={d.dataset_id}
              className="p-5 flex flex-col gap-4"
              data-testid={`dataset-${d.dataset_id}`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <h2 className="text-xl2 font-semibold truncate" title={d.display_name}>
                    {d.display_name}
                  </h2>
                  <p className="mono text-xs2 text-mute truncate" title={d.dataset_id}>
                    {d.dataset_id}
                  </p>
                </div>
                <Pill tone={kindTone(d.dataset_kind)}>
                  {d.dataset_kind.replace('_', ' ')}
                </Pill>
              </div>
              <dl className="grid grid-cols-3 gap-3">
                <div className="min-w-0">
                  <dt className="text-xs2 uppercase tracking-wider text-mute">Sessions</dt>
                  <dd className="mono text-sm2">{d.session_count}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-xs2 uppercase tracking-wider text-mute">Events</dt>
                  <dd className="mono text-sm2">{d.event_count}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-xs2 uppercase tracking-wider text-mute">Packets</dt>
                  <dd className="mono text-sm2">
                    {(d.packet_count ?? 0).toLocaleString('en-US')}
                  </dd>
                </div>
              </dl>
              <dl className="grid grid-cols-2 gap-3">
                <div className="min-w-0">
                  <dt className="text-xs2 uppercase tracking-wider text-mute">Source</dt>
                  <dd className="text-sm2 truncate" title={d.source}>
                    {d.source}
                  </dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-xs2 uppercase tracking-wider text-mute">Ingestion</dt>
                  <dd className="mono text-sm2">{d.ingestion_status}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-xs2 uppercase tracking-wider text-mute">Accounting</dt>
                  <dd className="mono text-sm2">{d.accounting_status ?? '—'}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-xs2 uppercase tracking-wider text-mute">Access</dt>
                  <dd className="text-sm2">{d.read_only ? 'Read-only' : 'Writable'}</dd>
                </div>
              </dl>
              <div className="flex flex-wrap gap-1.5 border-t border-line pt-3">
                {Object.entries(d.decoder_versions).map(([k, v]) => (
                  <span
                    key={k}
                    className="mono text-xs2 rounded border border-line px-1.5 py-0.5 text-mute"
                  >
                    {k} {v}
                  </span>
                ))}
              </div>
              <Link
                to={`/investigation/sessions?dataset_id=${encodeURIComponent(d.dataset_id)}`}
                className="self-start text-sm2 text-brand inline-flex items-center gap-1"
              >
                Open sessions <ArrowRight width={13} height={13} />
              </Link>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}
