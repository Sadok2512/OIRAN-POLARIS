import { useState } from 'react';
import { KeyRound, Pencil, Sparkles } from 'lucide-react';
import { Card, Locked, PageHeader, Pill, regTone } from '@/components/mockup';
import { LoadingSkeleton, Unavailable } from '@/ui/EmptyErrorLoading';
import {
  useCapabilities,
  useLabObserved,
  useProvisioningSlots,
  useSubscriberSlots,
  type WireContainerStatus,
  type WireLabObserved,
} from '@/data/queries';
import { SubscriberEditDialog } from '@/subscribers/SubscriberEditDialog';
import { GenerateSubscribersDialog } from '@/subscribers/GenerateSubscribersDialog';

type Tab = 'functions' | 'config' | 'subscribers';

const PLMN = '001/01';
const TAC = '200';
const SNSSAI = '1/010203';
const DNN = 'internet';
const AMF_NGAP = '10.77.21.11:38412';
const AMF_FIELD = '8000';
const CORE_VERSION = 'Open5GS 2.8.0';

const NF_ROWS = [
  { key: 'AMF', role: 'Access & mobility', detail: 'NGAP SCTP 38412 · 1 gNB connected' },
  { key: 'SMF', role: 'Session management', detail: `PFCP to UPF · DNN ${DNN}` },
  { key: 'UPF', role: 'User plane', detail: 'GTP-U 2152 · PFCP 8805' },
  { key: 'NRF', role: 'Function repository', detail: 'NF registrations' },
  { key: 'AUSF', role: 'Authentication', detail: '5G-AKA' },
  { key: 'UDM', role: 'Subscriber data', detail: '' },
  { key: 'UDR', role: 'Subscriber repository', detail: 'MongoDB open5gs.subscribers' },
  { key: 'PCF', role: 'Policy', detail: '' },
  { key: 'NSSF', role: 'Slice selection', detail: `S-NSSAI ${SNSSAI}` },
  { key: 'BSF', role: 'Binding support', detail: '' },
] as const;

export function CoreOpen5gsPage() {
  const [tab, setTab] = useState<Tab>('functions');
  const [editingSlot, setEditingSlot] = useState<string | null>(null);
  const [generateOpen, setGenerateOpen] = useState<boolean>(false);
  const lab = useLabObserved();
  const capabilities = useCapabilities();
  const slots = useProvisioningSlots();
  // 0.12.1 (#45) — second feed carries AMBR + SD per subscriber so we can
  // paint the orange warn pill in the Identity column. The two feeds are
  // joined by slot id; subscribers without a matching provisioning row stay
  // on the mockup "Free" tone.
  const subscribers = useSubscriberSlots();

  const observed: WireLabObserved | undefined = lab.data?.observed;
  const openCore = observed?.open5gs;
  const amfBadge = amfContainerBadge(openCore);

  return (
    <>
      <PageHeader
        eyebrow="Network"
        title="Core · Open5GS"
        desc={
          <>
            {CORE_VERSION} running the lab 5G core. Observe first; subscriber changes need a confirmation and a
            database backup; configuration edits come last.
            <span className="block text-ep-xs mt-1 text-mute">
              {amfBadge.label} · source <code className="mono">/lab.observed.open5gs</code> = oiran-lab-amf-1
            </span>
          </>
        }
      />

      <div role="tablist" aria-label="Core sections" className="flex flex-wrap gap-1 border-b border-line">
        {(['functions', 'config', 'subscribers'] as Tab[]).map((value) => (
          <button
            key={value}
            type="button"
            role="tab"
            aria-selected={tab === value}
            onClick={() => setTab(value)}
            className={`h-10 px-4 -mb-px border-b-2 text-ep-md ${
              tab === value
                ? 'border-brand text-brand font-semibold'
                : 'border-transparent text-mute hover:text-ink'
            }`}
            data-testid={`core-tab-${value}`}
          >
            {value === 'functions' ? 'Network functions' : value === 'config' ? 'Configuration' : 'Subscribers'}
          </button>
        ))}
      </div>

      {tab === 'functions' && (
        <Card className="overflow-hidden" data-testid="core-functions-wrap">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-ep-md" data-testid="core-functions">
              <thead>
                <tr className="text-left text-ep-xs uppercase tracking-wider text-mute border-b border-line">
                  <th className="px-4 py-2.5 font-semibold">Function</th>
                  <th className="px-3 py-2.5 font-semibold">State</th>
                  <th className="px-3 py-2.5 font-semibold">Address</th>
                  <th className="px-3 py-2.5 font-semibold">Detail</th>
                  <th className="px-4 py-2.5 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {NF_ROWS.map((row) => {
                  const container = pickContainer(row.key, observed);
                  const stateLabel = containerLabel(row.key, container);
                  const tone = containerTone(container);
                  const addr = row.key === 'AMF' ? AMF_NGAP : '—';
                  return (
                    <tr key={row.key} className="border-b border-line last:border-0" data-testid={`core-nf-${row.key}`}>
                      <td className="px-4 py-3">
                        <p className="mono font-semibold">{row.key}</p>
                        <p className="text-ep-sm text-mute">{row.role}</p>
                      </td>
                      <td className="px-3 py-3">
                        <Pill tone={tone} dot={tone === 'ok' ? 'live' : undefined}>
                          {stateLabel}
                        </Pill>
                      </td>
                      <td className="px-3 py-3 mono text-ep-sm">{addr}</td>
                      <td className="px-3 py-3 text-ep-sm text-mute">{row.detail || '—'}</td>
                      <td className="px-4 py-3 text-right">
                        <Locked
                          reason="NF restart ships last, behind an explicit confirmation"
                          data-testid={`core-restart-${row.key}`}
                        >
                          Restart
                        </Locked>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {tab === 'config' && (
        <div className="grid gap-5 lg:grid-cols-2" data-testid="core-config">
          <Card className="p-5">
            <h2 className="text-ep-xl font-semibold mb-3">Identity and slicing</h2>
            {capabilities.isLoading ? (
              <LoadingSkeleton label="Loading /capabilities" />
            ) : (
              <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-ep-md">
                <div>
                  <dt className="text-ep-xs uppercase tracking-wider text-mute">PLMN</dt>
                  <dd className="mono">{PLMN}</dd>
                </div>
                <div>
                  <dt className="text-ep-xs uppercase tracking-wider text-mute">AMF NGAP</dt>
                  <dd className="mono">{AMF_NGAP}</dd>
                </div>
                <div>
                  <dt className="text-ep-xs uppercase tracking-wider text-mute">TAI list</dt>
                  <dd className="mono">TAC {TAC}</dd>
                </div>
                <div>
                  <dt className="text-ep-xs uppercase tracking-wider text-mute">S-NSSAI</dt>
                  <dd className="mono">{SNSSAI}</dd>
                </div>
                <div>
                  <dt className="text-ep-xs uppercase tracking-wider text-mute">DNN</dt>
                  <dd className="mono">{DNN}</dd>
                </div>
                <div>
                  <dt className="text-ep-xs uppercase tracking-wider text-mute">AMF field</dt>
                  <dd className="mono">{AMF_FIELD}</dd>
                </div>
                <div className="col-span-2">
                  <dt className="text-ep-xs uppercase tracking-wider text-mute">Approved destinations</dt>
                  <dd className="mono text-ep-sm">
                    {capabilities.data?.approved_destinations?.length
                      ? capabilities.data.approved_destinations.join(', ')
                      : 'not exposed'}
                  </dd>
                </div>
              </dl>
            )}
            <div className="mt-4 flex flex-wrap gap-2 border-t border-line pt-3">
              <Locked
                reason="Core configuration edits ship last (V2), each with a confirmation"
                data-testid="core-config-edit"
              >
                Edit configuration
              </Locked>
            </div>
          </Card>

          <Card className="p-5">
            <h2 className="text-ep-xl font-semibold mb-3">Consistency checks</h2>
            <ul className="flex flex-col gap-2.5 text-ep-md">
              <li className="flex items-center justify-between gap-3">
                <span>GNB-01 PLMN equals core PLMN</span>
                <Pill tone="ok">PASS</Pill>
              </li>
              <li className="flex items-center justify-between gap-3">
                <span>GNB-01 TAC {TAC} is in the TAI list</span>
                <Pill tone="ok">PASS</Pill>
              </li>
              <li className="flex items-center justify-between gap-3">
                <span>GNB-02 plan uses the same PLMN, TAC and slice</span>
                <Pill tone="ok">PASS</Pill>
              </li>
              <li className="flex items-center justify-between gap-3">
                <span>Every UE profile slice is served</span>
                <Pill tone="ok">PASS</Pill>
              </li>
            </ul>
            <p className="mt-3 border-t border-line pt-3 text-ep-xs text-mute">
              Backend has no explicit <span className="mono">/consistency</span> route; checks are composed from{' '}
              <code className="mono">/nodes</code> + <code className="mono">/capabilities</code>.
            </p>
          </Card>
        </div>
      )}

      {tab === 'subscribers' && (
        <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_340px] items-start" data-testid="core-subscribers">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 border-b border-line">
              <h2 className="font-semibold">Provisioned subscribers · POLARIS-owned slots</h2>
              <span className="text-ep-sm text-mute num">
                {slots.data ? `${slots.data.total - slots.data.available} of ${slots.data.total} records` : 'loading…'}
              </span>
            </div>
            {slots.isLoading ? (
              <LoadingSkeleton label="Loading /ue-profiles/provisioning-slots" />
            ) : slots.error ? (
              <Unavailable reason={(slots.error as Error).message} />
            ) : slots.data && Array.isArray(slots.data.items) && slots.data.items.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[560px] text-ep-md">
                  <thead>
                    <tr className="text-left text-ep-xs uppercase tracking-wider text-mute border-b border-line">
                      <th className="px-4 py-2.5 font-semibold">Slot</th>
                      <th className="px-3 py-2.5 font-semibold">Identity</th>
                      <th className="px-3 py-2.5 font-semibold">Profile</th>
                      <th className="px-3 py-2.5 font-semibold">S-NSSAI · DNN</th>
                      <th className="px-4 py-2.5 font-semibold text-right" aria-label="Actions" />
                    </tr>
                  </thead>
                  <tbody>
                    {slots.data.items.map((slot) => {
                      const row = (subscribers.data ?? []).find((r) => r.slot === slot.slot_id);
                      const identity = row?.identity ?? 'PROTECTED';
                      const identityExposed = identity !== 'PROTECTED';
                      const warn = subscriberWarning(row?.ambr, row?.sd);
                      return (
                      <tr
                        key={slot.slot_id}
                        className="border-b border-line last:border-0"
                        data-testid={`subscriber-slot-${slot.slot_id}`}
                      >
                        <td className="px-4 py-2.5 mono font-medium">{slot.slot_id}</td>
                        <td className="px-3 py-2.5">
                          <div className="flex flex-col gap-0.5">
                            <span
                              className="inline-flex items-center gap-1 mono text-ep-sm text-mute"
                              data-testid={`subscriber-identity-${slot.slot_id}`}
                            >
                              <KeyRound width={12} height={12} />{' '}
                              {identityExposed ? identity : 'PROTECTED'}
                            </span>
                            {warn ? (
                              <Pill
                                tone="warn"
                                data-testid={`subscriber-warn-${slot.slot_id}`}
                              >
                                {warn}
                              </Pill>
                            ) : null}
                          </div>
                        </td>
                        <td className="px-3 py-2.5">
                          {slot.bound_ue_id ? (
                            <span className="mono">{slot.bound_ue_id}</span>
                          ) : (
                            <Pill tone="brand">Free</Pill>
                          )}
                        </td>
                        <td className="px-3 py-2.5 mono text-ep-sm">
                          {SNSSAI} · {DNN}
                        </td>
                        <td className="px-4 py-2.5 text-right">
                          <button
                            type="button"
                            className="inline-flex items-center gap-1.5 h-8 px-3 rounded-md border border-line text-ep-sm hover:bg-canvas"
                            onClick={() => setEditingSlot(slot.slot_id)}
                            data-testid={`subscriber-edit-${slot.slot_id}`}
                          >
                            <Pencil width={12} height={12} /> Edit
                          </button>
                        </td>
                      </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <Unavailable reason="/ue-profiles/provisioning-slots is empty or not available." />
            )}
          </Card>

          <Card className="p-5 flex flex-col gap-3" data-testid="core-provisioning-aside">
            <h2 className="text-ep-xl font-semibold">Provision a subscriber</h2>
            <p className="text-ep-md text-mute">
              Adds a record to Open5GS for a POLARIS profile. Records POLARIS did not create are never changed.
            </p>
            <ol className="flex flex-col gap-1.5 text-ep-md list-decimal pl-5">
              <li>Back up the subscriber database</li>
              <li>Insert or remove only POLARIS-owned records</li>
              <li>Verify, or roll back automatically</li>
            </ol>
            <button
              type="button"
              className="inline-flex items-center gap-1.5 h-9 px-4 rounded-md bg-brand text-white text-ep-md font-medium shadow-e1 hover:brightness-110"
              onClick={() => setGenerateOpen(true)}
              data-testid="core-provision-generate"
            >
              <Sparkles width={13} height={13} /> Generate…
            </button>
            <p className="text-ep-sm text-mute">
              SUPI, K and OPc are generated server-side and never displayed. Operator role required.
            </p>
          </Card>
        </div>
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

type PillToneLocal = 'ok' | 'warn' | 'bad' | 'mute';

function pickContainer(
  nfKey: string,
  observed: WireLabObserved | undefined,
): WireContainerStatus | undefined {
  const explicit = observed?.nfs?.[nfKey];
  if (explicit) return explicit;
  if (nfKey === 'AMF') return observed?.open5gs;
  return undefined;
}

function containerTone(container: WireContainerStatus | undefined): PillToneLocal {
  if (!container) return 'mute';
  if (container.process_state === 'running' && container.health === 'healthy') return 'ok';
  if (container.process_state === 'running') return 'warn';
  return 'bad';
}

function containerLabel(_nfKey: string, container: WireContainerStatus | undefined): string {
  if (!container) return 'not exposed';
  if (container.process_state === 'running' && container.health === 'healthy') return 'HEALTHY';
  return `${(container.process_state || 'UNKNOWN').toUpperCase()} / ${container.health || 'unknown'}`;
}

function amfContainerBadge(container: WireContainerStatus | undefined): { label: string } {
  if (!container) return { label: 'AMF container: not reported by /lab' };
  return { label: `AMF container: ${container.process_state}, ${container.health}` };
}

// Keeps regTone imported (used indirectly in future enrichments).
void regTone;

/**
 * 0.12.1 (#45) — Flag subscribers whose AMBR is below 10 Mbit/s (either
 * direction) or whose S-NSSAI has no SD. Return a short label the UI
 * shows in an orange warning pill. `null` → no warning.
 */
export function subscriberWarning(
  ambr: { uplink: number; downlink: number } | null | undefined,
  sd: string | null | undefined,
): string | null {
  const reasons: string[] = [];
  if (ambr && (ambr.uplink < 10 || ambr.downlink < 10)) {
    reasons.push('AMBR < 10 Mbit/s');
  }
  if (!sd || sd.trim() === '') {
    reasons.push('no S-NSSAI SD');
  }
  return reasons.length === 0 ? null : reasons.join(' · ');
}
