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

interface UeDetail {
  ue_id: string;
  identity: {
    name: string;
    owner: string;
    note: string | null;
    imsi: string;
    authentication: string;
  };
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
    bytes_dl: number;
    bytes_ul: number;
    last_sample_epoch_s: number | null;
  };
}

function useUeDetail(ueId: string, enabled: boolean) {
  return useQuery({
    queryKey: ['polaris', 'ue-detail', ueId],
    queryFn: () => polarisApi<UeDetail>(`/ue-profiles/${encodeURIComponent(ueId)}`),
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
            label="Authentication material"
            value="PROTECTED"
            mono
            protectedLabel
          />
        </Block>

        <Block title="Registration" testid="ue-block-registration">
          <Field
            label="State"
            value={detail.data?.registration.state ?? inventoryUe?.registration_state ?? '—'}
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
              <Field label="DL bytes" value={detail.data.traffic.bytes_dl.toLocaleString()} mono />
              <Field label="UL bytes" value={detail.data.traffic.bytes_ul.toLocaleString()} mono />
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

function formatEpoch(epochS: number | null): string {
  if (epochS == null) return '—';
  return new Date(epochS * 1000).toISOString().replace('T', ' ').replace('Z', ' UTC');
}
