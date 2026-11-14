// 0.6.0 — UE detail page.
// 0.12.1 (#51) — Hardened so the page never bails when the detail
// endpoint is unavailable:
//   * When `polarisProvisioning` is OFF (or returns 404) we compose a
//     fallback card from `/ues` (which is always reachable) so the
//     operator still sees the registration state, PDU, serving gNB and
//     a link to the full Activity timeline. Pre-0.12.1 the page just
//     printed "Backend pending" and became a dead end.
//   * Loading / error states keep the HeaderBar + "Back to UE Manager"
//     action visible, so there is no way to get stuck without a route
//     out.
//   * Identity material (IMSI, K / OPc) stays PROTECTED for viewers;
//     operators get the real IMSI via `formatImsiForRole` once the
//     backend ships it (polaris-api 0.19.7 #48 enables this on the
//     list endpoint; the per-slot endpoint follows the same rule).

import { useQuery } from '@tanstack/react-query';
import { useParams, Link } from 'react-router-dom';
import { AlertTriangle, ArrowLeft, Lock } from 'lucide-react';
import { Card, PageHeader } from '@/components/mockup';
import { LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import { polarisApi } from '@/data/polarisClient';
import { useFeatureFlag } from '@/data/featureFlags';
import { useAuth, useUes } from '@/data/queries';
import { formatImsiForRole } from '@/ue/imsiHelpers';
import { ApiError } from '@shared/api';

// 0.35.2 — `/ue-profiles/:id` now returns a FLAT profile (subscriber_identity,
// subscriber{…}, snssai, scenario_id, last_job…). The page used to read the
// legacy nested shape (identity.owner…) and crashed into a blank screen.
// Both shapes are normalised into `UeDetail`; a missing field renders as
// "—", never as an exception.
interface UeDetail {
  ue_id: string;
  identity: {
    name: string;
    owner: string;
    note: string | null;
    imsi: string;
    msisdn: string | null;
    authentication: string;
  };
  subscriber_dnns: string[];
  provisioning: {
    status: string;
    subscriber_id: string | null;
    bound_at_epoch_s: number | null;
  };
  network_profile: {
    plmn: { mcc: string; mnc: string };
    dnn: string;
    sst: number;
    sd: string | null;
    serving_gnb: string;
  };
  registration: {
    state: string;
    last_registered_at_epoch_s: number | null;
  };
  pdu_sessions: {
    id: number;
    dnn: string;
    type: string;
    ip: string | null;
    established_at_epoch_s: number | null;
  }[];
  ims: {
    state: string;
    reason: string | null;
  };
  scenario: {
    assigned_id: string | null;
    auto_run: boolean;
    last_job_id: string | null;
  };
  traffic: {
    bytes_dl: number | null;
    bytes_ul: number | null;
    last_sample_epoch_s: number | null;
  };
}

type Raw = Record<string, unknown>;
const obj = (v: unknown): Raw => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Raw) : {});
const str = (v: unknown): string | null => (typeof v === 'string' && v.length > 0 ? v : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

/** Accepts the legacy nested detail and the current flat profile. Exported for tests. */
export function normalizeUeDetail(input: unknown, ueId: string): UeDetail {
  const raw = obj(input);
  const legacyIdentity = obj(raw.identity);
  const subscriber = obj(raw.subscriber);
  const legacyNet = obj(raw.network_profile);
  const snssai = obj(raw.snssai ?? subscriber.snssai);
  const plmn = obj(legacyNet.plmn ?? raw.plmn ?? subscriber.plmn);
  const pdu = obj(raw.pdu_session);
  const legacyProv = obj(raw.provisioning);
  const legacyReg = obj(raw.registration);
  const legacyScen = obj(raw.scenario);
  const legacyTraffic = obj(raw.traffic);
  const lastJob = obj(raw.last_job);
  const ims = obj(raw.ims);
  const sessions = Array.isArray(raw.pdu_sessions) ? raw.pdu_sessions : [];
  return {
    ue_id: str(raw.ue_id) ?? ueId,
    identity: {
      name: str(legacyIdentity.name) ?? str(raw.name) ?? ueId,
      owner: str(legacyIdentity.owner) ?? str(raw.owner) ?? '—',
      note: str(legacyIdentity.note) ?? str(raw.note),
      imsi:
        str(legacyIdentity.imsi) ??
        str(raw.subscriber_identity) ??
        str(subscriber.subscriber_identity) ??
        '',
      msisdn: str(legacyIdentity.msisdn) ?? str(subscriber.msisdn) ?? str(raw.msisdn),
      authentication: 'PROTECTED',
    },
    subscriber_dnns: Array.isArray(subscriber.dnns)
      ? subscriber.dnns.filter((d): d is string => typeof d === 'string')
      : [],
    provisioning: {
      status: str(legacyProv.status) ?? str(raw.subscription_status) ?? str(subscriber.state) ?? '—',
      subscriber_id: str(legacyProv.subscriber_id) ?? str(subscriber.slot),
      bound_at_epoch_s: num(legacyProv.bound_at_epoch_s),
    },
    network_profile: {
      plmn: { mcc: str(plmn.mcc) ?? '—', mnc: str(plmn.mnc) ?? '—' },
      dnn: str(legacyNet.dnn) ?? str(raw.dnn) ?? str(pdu.dnn) ?? '—',
      sst: num(legacyNet.sst) ?? num(snssai.sst) ?? 0,
      sd: str(legacyNet.sd) ?? str(snssai.sd),
      serving_gnb: str(legacyNet.serving_gnb) ?? str(raw.serving_gnb) ?? '—',
    },
    registration: {
      state: str(legacyReg.state) ?? '—',
      last_registered_at_epoch_s: num(legacyReg.last_registered_at_epoch_s),
    },
    pdu_sessions: sessions.map((s, index) => {
      const row = obj(s);
      return {
        id: num(row.id) ?? num(row.psi) ?? index + 1,
        dnn: str(row.dnn) ?? '—',
        type: str(row.type) ?? '—',
        ip: str(row.ip) ?? str(row.address),
        established_at_epoch_s: num(row.established_at_epoch_s),
      };
    }),
    ims: { state: str(ims.state) ?? '—', reason: str(ims.reason) },
    scenario: {
      assigned_id: str(legacyScen.assigned_id) ?? str(raw.scenario_id),
      auto_run: legacyScen.auto_run === true || raw.auto_run_scenario === true,
      last_job_id: str(legacyScen.last_job_id) ?? str(lastJob.job_id),
    },
    traffic: {
      bytes_dl: num(legacyTraffic.bytes_dl) ?? num(lastJob.bytes_dl),
      bytes_ul: num(legacyTraffic.bytes_ul) ?? num(lastJob.bytes_ul),
      last_sample_epoch_s: num(legacyTraffic.last_sample_epoch_s),
    },
  };
}

function useUeDetail(ueId: string, enabled: boolean) {
  return useQuery({
    queryKey: ['polaris', 'ue-detail', ueId],
    queryFn: async () =>
      normalizeUeDetail(await polarisApi<unknown>(`/ue-profiles/${encodeURIComponent(ueId)}`), ueId),
    enabled,
    retry: false,
    staleTime: 10_000,
  });
}

export function UeDetailPage() {
  const { ueId = '' } = useParams();
  const enabled = useFeatureFlag('polarisProvisioning') && !!ueId;
  const detail = useUeDetail(ueId, enabled);
  const auth = useAuth();
  const ues = useUes();

  const canOperate = auth.data?.can_start === true;
  const inventoryUe = (ues.data?.items ?? []).find((item) => item.id === ueId);

  if (!ueId) {
    return (
      <>
        <HeaderBar ueId="—" />
        <Card className="p-4">
          <p className="text-ep-sm text-mute">No UE id in URL.</p>
        </Card>
      </>
    );
  }

  if (detail.isLoading) {
    return (
      <>
        <HeaderBar ueId={ueId} />
        <LoadingSkeleton label={`Loading /ue-profiles/${ueId}`} />
      </>
    );
  }

  const detailMissing = !enabled || detail.isError;
  const detailError =
    detail.isError && detail.error instanceof ApiError
      ? (detail.error as ApiError).code
      : detail.isError && detail.error
        ? (detail.error as Error).message
        : null;

  return (
    <>
      <HeaderBar ueId={ueId} />
      {detailMissing ? (
        <Card className="p-4 flex flex-col gap-2" data-testid="ue-detail-fallback">
          <p className="text-ep-sm text-mute">
            {enabled
              ? `Full detail endpoint returned ${detailError ?? 'an error'}. Showing the live
                inventory projection from /ues instead.`
              : 'Feature flag polarisProvisioning is OFF. Showing the live inventory projection from /ues.'}
          </p>
          <p className="text-ep-xs text-mute">
            <Link
              to={`/ues/${encodeURIComponent(ueId)}/activity`}
              className="underline"
              data-testid="ue-detail-activity-link"
            >
              Open the Activity timeline
            </Link>{' '}
            to see RM/CM/RRC/5GMM state, PDU, counters and events live.
          </p>
        </Card>
      ) : null}

      <div className="grid gap-3 md:grid-cols-2" data-testid="ue-detail-grid">
        <Block title="Identity" testid="ue-block-identity">
          <Field
            label="UE id"
            value={ueId}
            mono
          />
          <Field
            label="Owner"
            value={detail.data?.identity.owner ?? '—'}
            mono
          />
          <Field label="Note" value={detail.data?.identity.note ?? '—'} />
          <Field
            label="IMSI"
            value={formatImsiForRole(detail.data?.identity.imsi, canOperate)}
            mono
            protectedLabel={!canOperate}
          />
          <Field
            label="MSISDN"
            value={detail.data?.identity.msisdn ?? '-- (non provisionné)'}
            mono
          />
          <Field
            label="Authentication material"
            value="PROTECTED"
            mono
            protectedLabel
          />
          <p className="text-ep-xs pt-1">
            <Link
              to={`/ues/${encodeURIComponent(ueId)}/activity`}
              className="underline"
              data-testid="ue-detail-live-link"
            >
              Suivi en direct (RRC, enregistrement, PDU, débit)
            </Link>
          </p>
        </Block>

        <Block title="Registration" testid="ue-block-registration">
          <Field
            label="State"
            value={
              detail.data && detail.data.registration.state !== '—'
                ? detail.data.registration.state
                : inventoryUe?.registration_state ?? '—'
            }
          />
          <Field
            label="PDU session"
            value={inventoryUe?.pdu_session ?? '—'}
          />
          <Field
            label="UE IP"
            value={inventoryUe?.ue_ip ?? '—'}
            mono
          />
          <Field
            label="Serving gNB"
            value={inventoryUe?.serving_node ?? detail.data?.network_profile.serving_gnb ?? '—'}
            mono
          />
        </Block>

        {detail.data ? (
          <>
            <Block title="Provisioning" testid="ue-block-provisioning">
              <Field label="Status" value={detail.data.provisioning.status} />
              <Field
                label="Bound subscriber"
                value={detail.data.provisioning.subscriber_id ?? 'none'}
                mono
              />
              <Field
                label="Bound at"
                value={formatEpoch(detail.data.provisioning.bound_at_epoch_s)}
              />
            </Block>

            <Block title="Network profile" testid="ue-block-network">
              <Field
                label="PLMN"
                value={`${detail.data.network_profile.plmn.mcc}/${detail.data.network_profile.plmn.mnc}`}
                mono
              />
              <Field label="DNN" value={detail.data.network_profile.dnn} mono />
              <Field
                label="DNN autorisés"
                value={detail.data.subscriber_dnns.length ? detail.data.subscriber_dnns.join(', ') : '—'}
                mono
              />
              <Field label="S-NSSAI SST" value={String(detail.data.network_profile.sst)} mono />
              <Field label="S-NSSAI SD" value={detail.data.network_profile.sd ?? '—'} mono />
            </Block>

            <Block title="PDU sessions" testid="ue-block-pdu">
              {detail.data.pdu_sessions.length === 0 ? (
                <p className="text-ep-xs text-mute">No active PDU session.</p>
              ) : (
                <table className="text-ep-xs w-full">
                  <thead>
                    <tr>
                      <th className="text-left">#</th>
                      <th className="text-left">DNN</th>
                      <th className="text-left">Type</th>
                      <th className="text-left">IP</th>
                      <th className="text-left">Established</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.data.pdu_sessions.map((session) => (
                      <tr key={session.id} data-testid={`ue-pdu-row-${session.id}`}>
                        <td className="num">{session.id}</td>
                        <td className="mono">{session.dnn}</td>
                        <td>{session.type}</td>
                        <td className="mono">{session.ip ?? '—'}</td>
                        <td className="mono">{formatEpoch(session.established_at_epoch_s)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Block>

            <Block title="IMS" testid="ue-block-ims">
              <Field label="State" value={detail.data.ims.state} />
              {detail.data.ims.reason && (
                <p className="text-ep-xs text-warn flex items-start gap-1">
                  <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
                  {detail.data.ims.reason}
                </p>
              )}
            </Block>

            <Block title="Scenario" testid="ue-block-scenario">
              <Field label="Assigned id" value={detail.data.scenario.assigned_id ?? 'none'} mono />
              <Field
                label="Auto-run on start"
                value={detail.data.scenario.auto_run ? 'yes' : 'no'}
              />
              <Field label="Last job id" value={detail.data.scenario.last_job_id ?? 'none'} mono />
            </Block>

            <Block title="Traffic" testid="ue-block-traffic">
              <Field label="DL bytes" value={formatBytes(detail.data.traffic.bytes_dl)} mono />
              <Field label="UL bytes" value={formatBytes(detail.data.traffic.bytes_ul)} mono />
              <Field
                label="Last sample"
                value={formatEpoch(detail.data.traffic.last_sample_epoch_s)}
              />
            </Block>
          </>
        ) : null}
      </div>
    </>
  );
}

function HeaderBar({ ueId }: { ueId: string }) {
  return (
    <PageHeader
      eyebrow="Simulation"
      title={`UE ${ueId}`}
      desc="Detail composed from /ue-profiles/:ue_id with a /ues fallback when the backend endpoint is unavailable."
      actions={
        <Link
          to="/ues"
          className="inline-flex items-center gap-1.5 h-9 px-4 rounded-md border border-line text-ep-md font-medium hover:bg-canvas"
          data-testid="ue-detail-back"
        >
          <ArrowLeft width={14} height={14} />
          Back to UE Manager
        </Link>
      }
    />
  );
}

function Block({
  title,
  children,
  testid,
}: {
  title: string;
  children: React.ReactNode;
  testid: string;
}) {
  return (
    <Card className="p-4 flex flex-col gap-2" data-testid={testid}>
      <h2 className="text-ep-md font-semibold">{title}</h2>
      <div className="flex flex-col gap-1 text-ep-sm">{children}</div>
    </Card>
  );
}

function Field({
  label,
  value,
  mono,
  protectedLabel,
}: {
  label: string;
  value: string;
  mono?: boolean;
  protectedLabel?: boolean;
}) {
  return (
    <div className="grid grid-cols-[auto,1fr] gap-x-3">
      <span className="text-ep-xs uppercase tracking-wider text-mute pt-0.5">
        {label}
      </span>
      <span className={`${mono ? 'mono' : ''} flex items-center gap-1`}>
        {protectedLabel && <Lock width={11} height={11} className="text-mute" />}
        {value}
      </span>
    </div>
  );
}

function formatBytes(value: number | null): string {
  return value == null ? '-- (aucun run mesuré)' : value.toLocaleString();
}

function formatEpoch(epochS: number | null): string {
  if (epochS == null) return '—';
  return new Date(epochS * 1000).toISOString().replace('T', ' ').replace('Z', ' UTC');
}
