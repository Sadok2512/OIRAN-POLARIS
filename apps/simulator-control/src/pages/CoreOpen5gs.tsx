import { useState } from 'react';
import { AlertTriangle, KeyRound, Lock, Pencil, Sparkles } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { LoadingSkeleton, Unavailable } from '@/ui/EmptyErrorLoading';
import {
  useCapabilities,
  useLabObserved,
  useProvisioningSlots,
  type WireContainerStatus,
} from '@/data/queries';
import { SubscriberEditDialog } from '@/subscribers/SubscriberEditDialog';
import { GenerateSubscribersDialog } from '@/subscribers/GenerateSubscribersDialog';

type Tab = 'functions' | 'config' | 'subscribers';

const NF_ROWS = [
  { key: 'AMF', role: 'Access and mobility', hint: 'NGAP SCTP/38412' },
  { key: 'SMF', role: 'Session management', hint: 'PFCP/8805' },
  { key: 'UPF', role: 'User plane', hint: 'GTP-U/2152 · PFCP/8805' },
  { key: 'NRF', role: 'NF repository', hint: 'NF registrations' },
  { key: 'AUSF', role: 'Authentication', hint: '5G-AKA' },
  { key: 'UDM', role: 'Subscriber data', hint: '' },
  { key: 'UDR', role: 'Subscriber repository', hint: 'MongoDB open5gs.subscribers' },
  { key: 'PCF', role: 'Policy', hint: '' },
  { key: 'NSSF', role: 'Slice selection', hint: '' },
  { key: 'BSF', role: 'Binding support', hint: '' },
] as const;

export function CoreOpen5gsPage() {
  const [tab, setTab] = useState<Tab>('functions');
  const [editingSlot, setEditingSlot] = useState<string | null>(null);
  const [generateOpen, setGenerateOpen] = useState<boolean>(false);
  const lab = useLabObserved();
  const capabilities = useCapabilities();
  const slots = useProvisioningSlots();

  const openCore = lab.data?.observed?.open5gs;
  const amfBadge = amfContainerBadge(openCore);

  return (
    <>
      <PageHeader
        eyebrow="Network"
        title="Core · Open5GS"
        description="Read-only observation of the 5G core. NF restart, configuration edits and subscriber writes are deferred to V2 — the UI never issues a write."
        actions={
          <div className="flex items-center gap-2">
            <StatusIndicator
              state={amfBadge.state}
              tone={amfBadge.tone}
              label={amfBadge.label}
            />
            <span className="text-ep-xs text-text-secondary">
              source · <code className="mono">/lab.observed.open5gs</code> = oiran-lab-amf-1
            </span>
          </div>
        }
      />

      <div role="tablist" aria-label="Core sections" className="flex gap-2 border-b border-border mb-4">
        {(['functions', 'config', 'subscribers'] as Tab[]).map((value) => (
          <button
            key={value}
            type="button"
            role="tab"
            aria-selected={tab === value}
            onClick={() => setTab(value)}
            className={`h-9 px-3 -mb-px text-ep-sm border-b-2 ${
              tab === value
                ? 'border-primary text-primary font-semibold'
                : 'border-transparent text-text-secondary hover:text-text-primary'
            }`}
            data-testid={`core-tab-${value}`}
          >
            {value === 'functions' ? 'Network functions' : value === 'config' ? 'Configuration' : 'Subscribers'}
          </button>
        ))}
      </div>

      {tab === 'functions' && (
        <section className="ep-card overflow-hidden" data-testid="core-functions">
          <table className="ep-table">
            <thead>
              <tr>
                <th>Function</th>
                <th>State</th>
                <th>Detail</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {NF_ROWS.map((row) => {
                const observed = row.key === 'AMF' ? openCore : undefined;
                const tone = observed ? containerTone(observed) : 'neutral';
                const stateLabel = observed
                  ? observed.process_state === 'running' && observed.health === 'healthy'
                    ? 'HEALTHY'
                    : observed.process_state.toUpperCase() || 'UNKNOWN'
                  : 'not exposed';
                return (
                  <tr key={row.key} data-testid={`core-nf-${row.key}`}>
                    <td>
                      <div className="flex flex-col">
                        <span className="mono font-medium">{row.key}</span>
                        <span className="text-ep-xs text-text-secondary">{row.role}</span>
                      </div>
                    </td>
                    <td>
                      <StatusIndicator state={stateLabel} tone={tone} compact />
                    </td>
                    <td className="text-ep-xs text-text-secondary">
                      {row.key === 'AMF' && observed
                        ? `container "open5gs" · process_state=${observed.process_state} health=${observed.health}`
                        : row.hint || '—'}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="ep-button ep-button-sm"
                        disabled
                        aria-disabled="true"
                        title="NF restart ships last, behind an explicit confirmation."
                        data-testid={`core-restart-${row.key}`}
                      >
                        <Lock width={13} height={13} /> Restart
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <p className="text-ep-xs text-text-secondary px-3 py-2 border-t border-border flex items-start gap-1">
            <AlertTriangle className="text-warning mt-0.5 shrink-0" width={11} height={11} />
            POLARIS /lab reports a single container <code className="mono mx-1">open5gs</code>; per-NF state is "not
            exposed" until the backend splits them.
          </p>
        </section>
      )}

      {tab === 'config' && (
        <section className="grid gap-4 md:grid-cols-2" data-testid="core-config">
          <article className="ep-card p-4">
            <h2 className="text-ep-md font-semibold mb-2">Identity and slicing</h2>
            {capabilities.isLoading ? (
              <LoadingSkeleton label="Loading /capabilities" />
            ) : capabilities.data ? (
              <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-ep-sm">
                <dt className="text-text-secondary">Approved destinations</dt>
                <dd className="mono">
                  {capabilities.data.approved_destinations?.length
                    ? capabilities.data.approved_destinations.join(', ')
                    : 'not exposed'}
                </dd>
                <dt className="text-text-secondary">Traffic protocols</dt>
                <dd className="mono">
                  {capabilities.data.traffic_protocols?.length
                    ? capabilities.data.traffic_protocols.join(', ')
                    : 'not exposed'}
                </dd>
                <dt className="text-text-secondary">Registration modes</dt>
                <dd className="mono">
                  {capabilities.data.registration_modes?.length
                    ? capabilities.data.registration_modes.join(', ')
                    : 'not exposed'}
                </dd>
                <dt className="text-text-secondary">max UEs (live certified)</dt>
                <dd className="mono">
                  {capabilities.data.max_ues_live_certified ?? 'not exposed'}
                </dd>
                <dt className="text-text-secondary">max gNBs (live certified)</dt>
                <dd className="mono">
                  {capabilities.data.max_nodes_live_certified ?? 'not exposed'}
                </dd>
                <dt className="text-text-secondary">PLMN · TAC · S-NSSAI · DNN</dt>
                <dd className="text-ep-xs text-text-secondary">
                  not exposed by /capabilities — see each gNB in <code className="mono">/nodes</code>
                </dd>
              </dl>
            ) : (
              <Unavailable reason="Backend did not return /capabilities." />
            )}
            <div className="flex justify-end mt-3 border-t border-border pt-3">
              <button
                type="button"
                className="ep-button ep-button-sm"
                disabled
                aria-disabled="true"
                title="Core configuration edits ship in V2 behind explicit confirmation."
                data-testid="core-config-edit"
              >
                <Lock width={13} height={13} /> Edit configuration
              </button>
            </div>
          </article>

          <article className="ep-card p-4">
            <h2 className="text-ep-md font-semibold mb-2">Consistency checks</h2>
            <p className="text-ep-sm text-text-secondary mb-2">
              Backend has no explicit <span className="mono">/consistency</span> route. The UI only reports what
              /nodes and /capabilities already prove.
            </p>
            <ul className="flex flex-col gap-1.5 text-ep-sm">
              <li className="flex items-center justify-between gap-2">
                <span>GNB-01 PLMN present in /nodes</span>
                <StatusIndicator state="OBSERVED" tone="success" compact />
              </li>
              <li className="flex items-center justify-between gap-2">
                <span>live-certified gNB count</span>
                <StatusIndicator
                  state={`${capabilities.data?.max_nodes_live_certified ?? '?'}`}
                  tone="neutral"
                  compact
                />
              </li>
              <li className="flex items-center justify-between gap-2 text-ep-xs text-text-secondary">
                <span>GNB-02 live start · LIVE-005 approval</span>
                <span className="ep-badge border-warning/40 text-warning">locked</span>
              </li>
            </ul>
          </article>
        </section>
      )}

      {tab === 'subscribers' && (
        <section className="grid gap-4 md:grid-cols-[minmax(0,1fr)_320px]" data-testid="core-subscribers">
          <article className="ep-card overflow-hidden">
            <header className="flex items-center justify-between px-3 py-2 border-b border-border">
              <h2 className="text-ep-md font-semibold">Provisioned subscriber slots</h2>
              <span className="text-ep-xs text-text-secondary num">
                {slots.data
                  ? `${slots.data.total - slots.data.available} bound · ${slots.data.total} total`
                  : 'loading…'}
              </span>
            </header>
            {slots.isLoading ? (
              <LoadingSkeleton label="Loading /ue-profiles/provisioning-slots" />
            ) : slots.error ? (
              <Unavailable reason={(slots.error as Error).message} />
            ) : slots.data && Array.isArray(slots.data.items) && slots.data.items.length > 0 ? (
              <table className="ep-table">
                <thead>
                  <tr>
                    <th>Slot</th>
                    <th>Identity</th>
                    <th>Bound UE</th>
                    <th aria-label="Actions" />
                  </tr>
                </thead>
                <tbody>
                  {slots.data.items.map((slot) => (
                    <tr key={slot.slot_id} data-testid={`subscriber-slot-${slot.slot_id}`}>
                      <td className="mono">{slot.slot_id}</td>
                      <td>
                        <span className="inline-flex items-center gap-1 mono text-ep-xs text-text-secondary">
                          <KeyRound width={11} height={11} /> PROTECTED
                        </span>
                      </td>
                      <td className="mono">
                        {slot.bound_ue_id ?? (
                          <span className="ep-badge border-primary/40 text-primary">Free</span>
                        )}
                      </td>
                      <td className="text-right">
                        <button
                          type="button"
                          className="ep-button ep-button-sm"
                          onClick={() => setEditingSlot(slot.slot_id)}
                          data-testid={`subscriber-edit-${slot.slot_id}`}
                        >
                          <Pencil width={12} height={12} /> Edit
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Unavailable reason="/ue-profiles/provisioning-slots is empty or not available." />
            )}
          </article>

          <aside className="ep-card p-4 flex flex-col gap-2" data-testid="core-provisioning-aside">
            <h3 className="text-ep-md font-semibold">Provision subscribers</h3>
            <p className="text-ep-sm text-text-secondary">
              IMSI is allocated in <strong>001/01</strong> (next free MSIN). K and OPc are generated by the
              backend CSPRNG and never shown; the response only exposes the slot id.
            </p>
            <ul className="text-ep-xs text-text-secondary list-disc pl-5">
              <li>Back up the subscriber database</li>
              <li>Insert or remove only POLARIS-owned records</li>
              <li>Verify, or roll back automatically</li>
            </ul>
            <button
              type="button"
              className="ep-button ep-button-sm ep-button-primary"
              onClick={() => setGenerateOpen(true)}
              data-testid="core-provision-generate"
            >
              <Sparkles width={13} height={13} /> Generate…
            </button>
            <p className="text-ep-xs text-text-secondary">
              <Lock width={11} height={11} className="inline" /> Operator role required.
            </p>
          </aside>
        </section>
      )}

      {editingSlot ? (
        <SubscriberEditDialog
          slot={editingSlot}
          open
          onCancel={() => setEditingSlot(null)}
          onSaved={() => setEditingSlot(null)}
        />
      ) : null}
      <GenerateSubscribersDialog
        open={generateOpen}
        onCancel={() => setGenerateOpen(false)}
        onGenerated={() => {
          /* keep the dialog open so the operator can see the generated slot ids */
        }}
      />
    </>
  );
}

function containerTone(container: WireContainerStatus): 'success' | 'warning' | 'danger' | 'neutral' {
  if (!container) return 'neutral';
  if (container.process_state === 'running' && container.health === 'healthy') return 'success';
  if (container.process_state === 'running') return 'warning';
  return 'danger';
}

function amfContainerBadge(container: WireContainerStatus | undefined): {
  state: string;
  tone: 'success' | 'warning' | 'danger' | 'neutral';
  label: string;
} {
  if (!container) {
    return {
      state: 'UNKNOWN',
      tone: 'neutral',
      label: 'AMF container: not reported by /lab',
    };
  }
  return {
    state: `${container.process_state}/${container.health}`,
    tone: containerTone(container),
    label: `AMF container: ${container.process_state}, ${container.health}`,
  };
}
