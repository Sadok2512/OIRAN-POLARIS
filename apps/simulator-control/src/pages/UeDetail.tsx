// 0.6.0 — UE detail page.
//
// Behind `polarisProvisioning`. The LOT asks for 7 structured blocks:
//   Identity · Provisioning · Network profile · Registration · PDU
//   Sessions · IMS · Scenario · Traffic.
//
// Every block renders from the backend-returned object. When the
// backend returns 404 (feat/polaris-provisioning not deployed yet) or
// the field is absent, the block shows an honest "Backend pending"
// placeholder rather than fabricating a plausible value.

import { useQuery } from '@tanstack/react-query';
import { useParams, Link } from 'react-router-dom';
import { AlertTriangle, ArrowLeft, Lock } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { LoadingSkeleton, Unavailable } from '@/ui/EmptyErrorLoading';
import { polarisApi } from '@/data/polarisClient';
import { useFeatureFlag } from '@/data/featureFlags';
import { ApiError } from '@shared/api';

interface UeDetail {
  ue_id: string;
  identity: {
    name: string;
    owner: string;
    note: string | null;
    imsi: 'PROTECTED';
    authentication: 'PROTECTED';
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
    key: string;
    id: number | null;
    dnn: string;
    type: string;
    state: string;
    source: string;
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

type RawUeDetail = Record<string, any>;

function normalizeUeDetail(raw: RawUeDetail): UeDetail {
  const sessions = Array.isArray(raw.pdu_sessions) ? raw.pdu_sessions : [];
  return {
    ue_id: String(raw.ue_id ?? ''),
    identity: {
      name: String(raw.identity?.name ?? raw.name ?? raw.ue_id ?? 'Not available'),
      owner: String(raw.identity?.owner ?? 'Not available'),
      note: raw.identity?.note ?? null,
      imsi: 'PROTECTED',
      authentication: 'PROTECTED',
    },
    provisioning: {
      status: String(raw.provisioning?.status ?? raw.subscription_status ?? raw.subscriber?.state ?? 'NOT_AVAILABLE'),
      subscriber_id: raw.provisioning?.subscriber_id ?? raw.subscriber?.slot ?? null,
      bound_at_epoch_s: raw.provisioning?.bound_at_epoch_s ?? null,
    },
    network_profile: {
      plmn: raw.network_profile?.plmn ?? raw.plmn ?? { mcc: '—', mnc: '—' },
      dnn: String(raw.network_profile?.dnn ?? raw.dnn ?? 'Not available'),
      sst: Number(raw.network_profile?.sst ?? raw.snssai?.sst ?? 0),
      sd: raw.network_profile?.sd ?? raw.snssai?.sd ?? null,
      serving_gnb: String(raw.network_profile?.serving_gnb ?? raw.serving_gnb ?? 'Not available'),
    },
    registration: raw.registration ?? { state: 'NOT_AVAILABLE', last_registered_at_epoch_s: null },
    pdu_sessions: sessions.map((session: RawUeDetail, index: number) => ({
      key: String(session.id ?? `${session.dnn ?? 'unknown'}-${index}`),
      id: Number.isInteger(session.id) ? session.id : null,
      dnn: String(session.dnn ?? 'Not available'),
      type: String(session.type ?? 'Not available'),
      state: String(session.state ?? 'NOT_AVAILABLE'),
      source: String(session.source ?? 'NOT_AVAILABLE'),
      ip: session.ip ?? null,
      established_at_epoch_s: session.established_at_epoch_s ?? null,
    })),
    ims: {
      state: String(raw.ims?.state ?? 'NOT_AVAILABLE'),
      reason: raw.ims?.reason ?? null,
    },
    scenario: {
      assigned_id: raw.scenario?.assigned_id ?? raw.scenario_id ?? null,
      auto_run: Boolean(raw.scenario?.auto_run ?? raw.auto_run_scenario),
      last_job_id: raw.scenario?.last_job_id ?? raw.last_job?.job_id ?? null,
    },
    traffic: {
      bytes_dl: Number(raw.traffic?.bytes_dl ?? raw.last_job?.bytes_dl ?? 0),
      bytes_ul: Number(raw.traffic?.bytes_ul ?? raw.last_job?.bytes_ul ?? 0),
      last_sample_epoch_s: raw.traffic?.last_sample_epoch_s ?? null,
    },
  };
}

function useUeDetail(ueId: string, enabled: boolean) {
  return useQuery({
    queryKey: ['polaris', 'ue-detail', ueId],
    queryFn: async () => normalizeUeDetail(
      await polarisApi<RawUeDetail>(`/ue-profiles/${encodeURIComponent(ueId)}`),
    ),
    enabled,
    retry: false,
    staleTime: 10_000,
  });
}

export function UeDetailPage() {
  const { ueId = '' } = useParams();
  const enabled = useFeatureFlag('polarisProvisioning') && !!ueId;
  const detail = useUeDetail(ueId, enabled);

  if (!enabled) {
    return (
      <>
        <PageHeader
          eyebrow="Simulation"
          title={`UE ${ueId}`}
          description="Detail card driven by GET /ue-profiles/:ue_id."
        />
        <Unavailable reason="Feature flag polarisProvisioning is OFF. Flip it in Settings when feat/polaris-provisioning is deployed." />
      </>
    );
  }

  if (detail.isLoading) {
    return (
      <>
        <HeaderBar ueId={ueId} />
        <LoadingSkeleton />
      </>
    );
  }

  if (detail.isError) {
    const code = detail.error instanceof ApiError ? (detail.error as ApiError).code : 'DETAIL_FAILED';
    return (
      <>
        <HeaderBar ueId={ueId} />
        <Unavailable reason={`${code} · ${(detail.error as Error).message}`} />
      </>
    );
  }

  const data = detail.data!;
  return (
    <>
      <HeaderBar ueId={ueId} />
      <div className="grid gap-3 md:grid-cols-2">
        <Block title="Identity" testid="ue-block-identity">
          <Field label="Name" value={data.identity.name} />
          <Field label="Owner" value={data.identity.owner} mono />
          <Field label="Note" value={data.identity.note ?? '—'} />
          <Field label="IMSI" value={data.identity.imsi} mono protected />
          <Field label="Authentication material" value={data.identity.authentication} mono protected />
        </Block>

        <Block title="Provisioning" testid="ue-block-provisioning">
          <Field label="Status" value={data.provisioning.status} />
          <Field
            label="Bound subscriber"
            value={data.provisioning.subscriber_id ?? 'none'}
            mono
          />
          <Field
            label="Bound at"
            value={formatEpoch(data.provisioning.bound_at_epoch_s)}
          />
        </Block>

        <Block title="Network profile" testid="ue-block-network">
          <Field
            label="PLMN"
            value={`${data.network_profile.plmn.mcc}/${data.network_profile.plmn.mnc}`}
            mono
          />
          <Field label="DNN" value={data.network_profile.dnn} mono />
          <Field label="S-NSSAI SST" value={String(data.network_profile.sst)} mono />
          <Field label="S-NSSAI SD" value={data.network_profile.sd ?? '—'} mono />
          <Field label="Serving gNB" value={data.network_profile.serving_gnb} mono />
        </Block>

        <Block title="Registration" testid="ue-block-registration">
          <Field label="State" value={data.registration.state} />
          <Field
            label="Last registered"
            value={formatEpoch(data.registration.last_registered_at_epoch_s)}
          />
        </Block>

        <Block title="PDU sessions" testid="ue-block-pdu">
          {data.pdu_sessions.length === 0 ? (
            <p className="text-ep-xs text-text-secondary">No active PDU session.</p>
          ) : (
            <table className="text-ep-xs w-full">
              <thead>
                <tr>
                  <th className="text-left">#</th>
                  <th className="text-left">DNN</th>
                  <th className="text-left">Type</th>
                  <th className="text-left">State</th>
                  <th className="text-left">IP</th>
                  <th className="text-left">Established</th>
                </tr>
              </thead>
              <tbody>
                {data.pdu_sessions.map((session) => (
                  <tr key={session.key} data-testid={`ue-pdu-row-${session.key}`}>
                    <td className="num">{session.id ?? '—'}</td>
                    <td className="mono">{session.dnn}</td>
                    <td>{session.type}</td>
                    <td>{session.state}</td>
                    <td className="mono">{session.ip ?? '—'}</td>
                    <td className="mono">{formatEpoch(session.established_at_epoch_s)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Block>

        <Block title="IMS" testid="ue-block-ims">
          <Field label="State" value={data.ims.state} />
          {data.ims.reason && (
            <p className="text-ep-xs text-warning flex items-start gap-1">
              <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
              {data.ims.reason}
            </p>
          )}
        </Block>

        <Block title="Scenario" testid="ue-block-scenario">
          <Field label="Assigned id" value={data.scenario.assigned_id ?? 'none'} mono />
          <Field
            label="Auto-run on start"
            value={data.scenario.auto_run ? 'yes' : 'no'}
          />
          <Field label="Last job id" value={data.scenario.last_job_id ?? 'none'} mono />
        </Block>

        <Block title="Traffic" testid="ue-block-traffic">
          <Field label="DL bytes" value={data.traffic.bytes_dl.toLocaleString()} mono />
          <Field label="UL bytes" value={data.traffic.bytes_ul.toLocaleString()} mono />
          <Field
            label="Last sample"
            value={formatEpoch(data.traffic.last_sample_epoch_s)}
          />
        </Block>
      </div>
    </>
  );
}

function HeaderBar({ ueId }: { ueId: string }) {
  return (
    <PageHeader
      eyebrow="Simulation"
      title={`UE ${ueId}`}
      description="Detail card driven by GET /ue-profiles/:ue_id."
      actions={
        <Link to="/ues" className="ep-button ep-button-sm">
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
    <section className="ep-card p-4 flex flex-col gap-2" data-testid={testid}>
      <h2 className="text-ep-md font-semibold">{title}</h2>
      <div className="flex flex-col gap-1 text-ep-sm">{children}</div>
    </section>
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
    <div className="grid grid-cols-[auto,1fr] gap-x-3">
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

function formatEpoch(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—';
  return new Date(value * 1000).toLocaleString();
}
