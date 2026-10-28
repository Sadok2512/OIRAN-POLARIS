// 0.6.0 — Provisioning page.
//
// Lives behind the `polarisProvisioning` flag. The LOT asks for:
//   * subscriber list from GET /subscribers (contract on Codex's branch)
//   * single-row add dialog with masked IMSI
//   * CSV import up to 100 000 rows with progress + per-line error report
// Nothing is persisted locally; when the backend returns 404 we show the
// honest "Backend pending" placeholder instead of fabricating fixtures.

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, FileUp, Plus, Users } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { EmptyState, LoadingSkeleton, Unavailable } from '@/ui/EmptyErrorLoading';
import { useFeatureFlag } from '@/data/featureFlags';
import { polarisApi } from '@/data/polarisClient';
import { CsvImportDialog } from '@/components/CsvImportDialog';
import { ApiError } from '@shared/api';

interface Subscriber {
  subscriber_id: string;
  owner: string;
  imsi: 'PROTECTED';
  provisioning_status: string;
  updated_at_epoch_s: number;
}

interface SubscriberList {
  items: Subscriber[];
  total: number;
}

function useSubscribers(enabled: boolean) {
  return useQuery({
    queryKey: ['polaris', 'subscribers'],
    queryFn: () => polarisApi<SubscriberList>('/subscribers'),
    enabled,
    retry: false,
    staleTime: 15_000,
  });
}

export function ProvisioningPage() {
  const enabled = useFeatureFlag('polarisProvisioning');
  const [csvOpen, setCsvOpen] = useState(false);
  const subscribers = useSubscribers(enabled);

  if (!enabled) {
    return (
      <>
        <PageHeader
          eyebrow="Platform"
          title="Provisioning"
          description="Subscriber directory synchronised with Open5GS. One source of truth for IMSI → PLMN → gNB bindings."
        />
        <Unavailable
          reason="Feature flag polarisProvisioning is OFF. Flip it in Settings when the backend branch feat/polaris-provisioning is deployed."
        />
      </>
    );
  }

  const errorCode =
    subscribers.error instanceof ApiError ? (subscribers.error as ApiError).code : 'LIST_FAILED';

  return (
    <>
      <PageHeader
        eyebrow="Platform"
        title="Provisioning"
        description="Subscriber directory. Add one subscriber at a time or import a CSV (≤ 100 000 rows). SUPI / K / OPc are never persisted in the browser."
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={() => setCsvOpen(true)}
              data-testid="provisioning-import"
            >
              <FileUp width={13} height={13} /> Import CSV
            </button>
            <button
              type="button"
              className="ep-button ep-button-sm ep-button-primary"
              disabled
              title="Single-add dialog ships with the backend contract on feat/polaris-provisioning."
              data-testid="provisioning-add"
            >
              <Plus width={13} height={13} /> Add subscriber
            </button>
          </div>
        }
      />

      <section className="ep-card p-5">
        {subscribers.isLoading ? (
          <LoadingSkeleton />
        ) : subscribers.isError ? (
          <Unavailable reason={`${errorCode} · ${(subscribers.error as Error).message}`} />
        ) : !subscribers.data || subscribers.data.items.length === 0 ? (
          <EmptyState
            title="No subscriber yet"
            description="Add one through the dialog once the backend ships, or import a CSV."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="ep-table" data-testid="provisioning-subscribers">
              <thead>
                <tr>
                  <th>Subscriber id</th>
                  <th>Owner</th>
                  <th>IMSI</th>
                  <th>Status</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {subscribers.data.items.map((item) => (
                  <tr key={item.subscriber_id} data-testid={`subscriber-row-${item.subscriber_id}`}>
                    <td className="mono">{item.subscriber_id}</td>
                    <td>{item.owner}</td>
                    <td className="mono">{item.imsi}</td>
                    <td>{item.provisioning_status}</td>
                    <td className="num">{item.updated_at_epoch_s}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <CsvImportDialog
        open={csvOpen}
        onClose={() => setCsvOpen(false)}
        target="provisioning"
        title="Import subscribers (CSV)"
        description="One subscriber per line. Expected header: subscriber_id,owner,imsi,authentication_key,opc,plmn_mcc,plmn_mnc. The backend validates every row and returns an error list."
      />

      {subscribers.data && (
        <aside className="text-ep-xs text-text-secondary mt-2 flex items-start gap-1">
          <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
          <Users width={11} height={11} className="mt-0.5 shrink-0" />
          <span>
            {subscribers.data.total.toLocaleString()} subscribers in the backend directory.
          </span>
        </aside>
      )}
    </>
  );
}
