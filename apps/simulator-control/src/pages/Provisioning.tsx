// 0.6.0 / 0.7.1 — Provisioning page.
//
// Lives behind the `polarisProvisioning` flag:
//   * subscriber list from GET /subscribers
//   * single-row Add dialog + CSV import (≤ 100 000 rows)
//   * 0.7.1 — row click opens a detail panel sourced from
//     GET /subscribers/:slot. Edit button is present but locked until
//     the backend ships PUT /subscribers/:slot.
//
// Nothing is persisted locally; 404 renders an honest "Backend pending"
// placeholder instead of fabricating fixtures.

import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, Edit3, FileUp, Lock, Plus, Users, X } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { EmptyState, LoadingSkeleton, Unavailable } from '@/ui/EmptyErrorLoading';
import { useFeatureFlag } from '@/data/featureFlags';
import { polarisApi } from '@/data/polarisClient';
import { CsvImportDialog } from '@/components/CsvImportDialog';
import { AddSubscriberDialog } from '@/subscribers/AddSubscriberDialog';
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

/**
 * 0.7.1 — Richer per-slot body served by GET /subscribers/:slot. All
 * secret fields come back as `PROTECTED`.
 */
export interface SubscriberDetail {
  slot_id: string;
  subscriber_id: string;
  provisioning_status: string;
  plmn: { mcc: string; mnc: string };
  slice: { sst: number; sd: string | null };
  dnns: string[];
  ambr: { uplink: number; downlink: number };
  bound_ues: string[];
  imsi: 'PROTECTED';
  k: 'PROTECTED';
  opc: 'PROTECTED';
  updated_at_epoch_s: number;
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

function useSubscriberDetail(slot: string | null, enabled: boolean) {
  return useQuery({
    queryKey: ['polaris', 'subscriber-detail', slot],
    queryFn: () => polarisApi<SubscriberDetail>(`/subscribers/${encodeURIComponent(slot!)}`),
    enabled: enabled && !!slot,
    retry: false,
    staleTime: 10_000,
  });
}

export function ProvisioningPage() {
  const enabled = useFeatureFlag('polarisProvisioning');
  const [csvOpen, setCsvOpen] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [selectedSlot, setSelectedSlot] = useState<string | null>(null);
  const subscribers = useSubscribers(enabled);
  const queryClient = useQueryClient();

  if (!enabled) {
    return (
      <>
        <PageHeader
          eyebrow="Platform"
          title="Provisioning"
          description="Subscriber directory synchronised with Open5GS. One source of truth for IMSI → PLMN → gNB bindings."
        />
        <Unavailable
          reason="Feature flag polarisProvisioning is OFF. Flip it in Settings to re-enable the subscriber directory."
          data-testid="provisioning-flag-off"
        />
      </>
    );
  }

  // 0.9.2 — if the backend surface is genuinely unavailable, surface the
  // exact HTTP status + backend code + message. No "backend pending"
  // placeholder: operators see the real failure, not a flattened label.
  const errorStatus =
    subscribers.error instanceof ApiError ? (subscribers.error as ApiError).status : null;
  const errorCode =
    subscribers.error instanceof ApiError ? (subscribers.error as ApiError).code : 'LIST_FAILED';
  const errorMessage =
    subscribers.error instanceof Error
      ? subscribers.error.message
      : subscribers.error == null
      ? ''
      : String(subscribers.error);
  // POLARIS returns `{error: "CODE"}` (string), which the client expands into
  // `code=CODE, message=CODE`. Deduplicate so operators don't see the same
  // string twice; the OIRAN-style `{error: {code, message}}` keeps both.
  const errorReason = [
    errorStatus != null ? `HTTP ${errorStatus}` : null,
    errorCode,
    errorMessage && errorMessage !== errorCode ? errorMessage : null,
  ]
    .filter(Boolean)
    .join(' · ');

  return (
    <>
      <PageHeader
        eyebrow="Platform"
        title="Provisioning"
        description="Subscriber directory. Click a row to see the slot detail (slice, DNN, AMBR, bound UEs). SUPI / K / OPc are never persisted in the browser."
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
              onClick={() => setAddOpen(true)}
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
          <Unavailable
            reason={errorReason}
            data-testid="provisioning-list-error"
          />
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
                  <tr
                    key={item.subscriber_id}
                    data-testid={`subscriber-row-${item.subscriber_id}`}
                    className="cursor-pointer hover:bg-canvas/40"
                    onClick={() => setSelectedSlot(item.subscriber_id)}
                  >
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
        target="subscribers"
        title="Import subscribers (CSV)"
        description="POST /subscribers/bulk (text/csv). Expected header: imsi,k,opc,sst,sd,dnns,ambr_uplink,ambr_downlink. The backend validates every row and returns an error list."
        onImported={() => queryClient.invalidateQueries({ queryKey: ['polaris', 'subscribers'] })}
      />

      <AddSubscriberDialog
        open={addOpen}
        onClose={() => setAddOpen(false)}
        onCreated={() => queryClient.invalidateQueries({ queryKey: ['polaris', 'subscribers'] })}
      />

      <SubscriberDetailPanel
        slot={selectedSlot}
        onClose={() => setSelectedSlot(null)}
        enabled={enabled}
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

function SubscriberDetailPanel({
  slot,
  onClose,
  enabled,
}: {
  slot: string | null;
  onClose: () => void;
  enabled: boolean;
}) {
  const detail = useSubscriberDetail(slot, enabled);
  if (!slot) return null;

  const code = detail.error instanceof ApiError ? (detail.error as ApiError).code : 'DETAIL_FAILED';

  return (
    <aside
      role="dialog"
      aria-modal="true"
      aria-labelledby="subscriber-detail-title"
      className="fixed inset-0 z-40 flex items-start justify-end bg-black/40 p-4"
      data-testid="subscriber-detail-panel"
    >
      <div className="ep-card w-full max-w-md p-5 flex flex-col gap-3 h-full overflow-y-auto">
        <header className="flex items-center justify-between gap-2">
          <div className="min-w-0">
            <p className="text-ep-xs uppercase tracking-wider text-text-secondary">Slot</p>
            <h2 id="subscriber-detail-title" className="text-ep-lg font-semibold mono truncate">
              {slot}
            </h2>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="ep-button ep-button-sm opacity-60 cursor-not-allowed"
              disabled
              title="Backend pending: PUT /subscribers/:slot"
              data-testid="subscriber-detail-edit"
            >
              <Edit3 width={13} height={13} /> Edit
            </button>
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={onClose}
              aria-label="Close"
              data-testid="subscriber-detail-close"
            >
              <X width={13} height={13} />
            </button>
          </div>
        </header>

        <p className="text-ep-xs text-warning flex items-start gap-1">
          <Lock width={11} height={11} className="mt-0.5 shrink-0" />
          Edit stays locked until the backend ships{' '}
          <code className="mono mx-1">PUT /subscribers/:slot</code>.
        </p>

        {detail.isLoading && <LoadingSkeleton label="Loading /subscribers/:slot" />}
        {detail.isError && !detail.isLoading && (
          <Unavailable reason={`${code} · ${(detail.error as Error).message}`} />
        )}
        {detail.data && (
          <div className="flex flex-col gap-3">
            <section data-testid="subscriber-detail-identity">
              <h3 className="text-ep-sm font-semibold mb-1">Identity</h3>
              <Field label="Subscriber id" value={detail.data.subscriber_id} mono />
              <Field label="State" value={detail.data.provisioning_status} />
              <Field label="IMSI" value={detail.data.imsi} mono protected />
              <Field label="K" value={detail.data.k} mono protected />
              <Field label="OPc" value={detail.data.opc} mono protected />
            </section>

            <section data-testid="subscriber-detail-network">
              <h3 className="text-ep-sm font-semibold mb-1">Network</h3>
              <Field
                label="PLMN"
                value={`${detail.data.plmn.mcc}/${detail.data.plmn.mnc}`}
                mono
              />
              <Field
                label="Slice"
                value={`SST ${detail.data.slice.sst}${detail.data.slice.sd ? ` / SD ${detail.data.slice.sd}` : ''}`}
                mono
              />
              <Field label="DNNs" value={detail.data.dnns.join(', ') || '—'} mono />
            </section>

            <section data-testid="subscriber-detail-ambr">
              <h3 className="text-ep-sm font-semibold mb-1">AMBR</h3>
              <Field
                label="Uplink"
                value={`${detail.data.ambr.uplink.toLocaleString()} kbps`}
                mono
              />
              <Field
                label="Downlink"
                value={`${detail.data.ambr.downlink.toLocaleString()} kbps`}
                mono
              />
            </section>

            <section data-testid="subscriber-detail-bound-ues">
              <h3 className="text-ep-sm font-semibold mb-1">Bound UEs · {detail.data.bound_ues.length}</h3>
              {detail.data.bound_ues.length === 0 ? (
                <p className="text-ep-xs text-text-secondary">No UE bound to this slot yet.</p>
              ) : (
                <ul className="flex flex-wrap gap-1">
                  {detail.data.bound_ues.map((ueId) => (
                    <li key={ueId}>
                      <span className="ep-badge mono">{ueId}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        )}
      </div>
    </aside>
  );
}

function Field({
  label,
  value,
  mono,
  protected: isProtected,
}: {
  label: string;
  value: string;
  mono?: boolean;
  protected?: boolean;
}) {
  return (
    <div className="grid grid-cols-[8rem,1fr] gap-x-3 text-ep-sm">
      <span className="text-ep-xs uppercase tracking-wider text-text-secondary pt-0.5">
        {label}
      </span>
      <span className={`${mono ? 'mono' : ''} flex items-center gap-1`}>
        {isProtected && <Lock width={11} height={11} className="text-text-secondary" />}
        {value}
      </span>
    </div>
  );
}
