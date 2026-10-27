import { useState } from 'react';
import { PageHeader } from '@/ui/PageHeader';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from '@/ui/EmptyErrorLoading';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { useDataset, useDatasets } from '@/data/queries';
import { count } from '@/data/format';

export function DatasetsPage() {
  const datasets = useDatasets();
  const [selected, setSelected] = useState<string | null>(null);
  const detail = useDataset(selected);

  return (
    <>
      <PageHeader
        eyebrow="Analysis"
        title="Datasets"
        description="Every dataset reported by the backend. Historical, captured-live and recovered datasets live side by side with their accounting."
      />
      {datasets.isLoading && <LoadingSkeleton label="Loading datasets" />}
      {datasets.error && (
        <ErrorState
          title="Could not load datasets"
          detail={(datasets.error as Error).message}
          onRetry={() => void datasets.refetch()}
        />
      )}
      {!datasets.isLoading && (datasets.data?.length ?? 0) === 0 && (
        <EmptyState
          title="No dataset reported"
          description="The backend has not registered any dataset yet."
        />
      )}
      {(datasets.data?.length ?? 0) > 0 && (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
          <div className="ep-card overflow-hidden">
            <table className="ep-table" data-testid="datasets-table">
              <thead>
                <tr>
                  <th>Dataset</th>
                  <th>Kind</th>
                  <th>Technology</th>
                  <th>Sessions</th>
                  <th>UEs</th>
                  <th>Events</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {datasets.data!.map((ds) => (
                  <tr
                    key={ds.dataset_id}
                    onClick={() => setSelected(ds.dataset_id)}
                    data-selected={selected === ds.dataset_id}
                    className="cursor-pointer"
                  >
                    <td>
                      <div className="flex flex-col">
                        <span className="font-medium">{ds.display_name}</span>
                        <span className="text-text-secondary text-ep-xs mono truncate">
                          {ds.dataset_id}
                        </span>
                      </div>
                    </td>
                    <td><span className="ep-badge">{ds.dataset_kind}</span></td>
                    <td>{ds.technology}</td>
                    <td className="num">{count(ds.session_count)}</td>
                    <td className="num">{count(ds.ue_context_count)}</td>
                    <td className="num">{count(ds.event_count)}</td>
                    <td><StatusIndicator state={ds.ingestion_status} compact /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <aside className="ep-card p-4" aria-label="Dataset inspector">
            {!selected ? (
              <EmptyState title="Pick a dataset" description="Select a row to see detailed accounting." />
            ) : detail.isLoading ? (
              <LoadingSkeleton label="Loading dataset" />
            ) : detail.error ? (
              <ErrorState title="Load failed" detail={(detail.error as Error).message} />
            ) : detail.data ? (
              <>
                <h3 className="text-ep-lg font-semibold mb-2">{detail.data.display_name}</h3>
                <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-ep-sm">
                  <dt className="text-text-secondary">Source</dt>
                  <dd>{detail.data.source}</dd>
                  <dt className="text-text-secondary">Ingestion</dt>
                  <dd>{detail.data.ingestion_status}</dd>
                  <dt className="text-text-secondary">PDU sessions</dt>
                  <dd className="num">{count(detail.data.pdu_session_count)}</dd>
                  <dt className="text-text-secondary">Normalized events</dt>
                  <dd className="num">{count(detail.data.normalized_event_count)}</dd>
                  <dt className="text-text-secondary">Packets</dt>
                  <dd className="num">{count(detail.data.packet_count)}</dd>
                  <dt className="text-text-secondary">Background events</dt>
                  <dd className="num">{count(detail.data.background_event_count)}</dd>
                  <dt className="text-text-secondary">Unmatched events</dt>
                  <dd className="num">{count(detail.data.unmatched_event_count)}</dd>
                  <dt className="text-text-secondary">Duplicate observations</dt>
                  <dd className="num">{count(detail.data.duplicate_observation_count)}</dd>
                  <dt className="text-text-secondary">Errors</dt>
                  <dd className="num">{count(detail.data.error_count)}</dd>
                  <dt className="text-text-secondary">Read only</dt>
                  <dd>{detail.data.read_only ? 'Yes' : 'No'}</dd>
                </dl>
                <a
                  className="ep-button ep-button-sm ep-button-primary mt-4"
                  href={`/analyzer/investigation/sessions?dataset_id=${encodeURIComponent(detail.data.dataset_id)}`}
                >
                  Open in Session Explorer
                </a>
              </>
            ) : null}
          </aside>
        </div>
      )}
    </>
  );
}
