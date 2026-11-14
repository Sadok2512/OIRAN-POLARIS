import { Card, PageHeader, Pill } from '@/components/mockup';
import {
  ErrorState,
  LoadingSkeleton,
} from '@/ui/EmptyErrorLoading';
import {
  useLab,
  useLabObserved,
  useNodes,
  useScenarioHistory,
  useScenarioRuntime,
  useSystemHealth,
  useUes,
} from '@/data/queries';

const NOT_AVAILABLE = 'NOT_AVAILABLE';

export function diskMeasurementView(
  health: ReturnType<typeof useSystemHealth>['data'],
  error: Error | null,
): { error: string | null; usage: string | null } {
  if (error) return { error: error.message, usage: null };
  if (!health?.disk) {
    return {
      error: health?.disk_measurement_error ?? health?.decision.reason ?? 'SONDE_DISQUE_SANS_RESULTAT',
      usage: null,
    };
  }
  return { error: null, usage: `${health.disk.usage_percent.toFixed(2)} % utilisés` };
}

type ReadinessRow = {
  label: string;
  status: 'pass' | 'warn' | 'fail';
  detail?: string;
};

function Readiness({
  rows,
}: {
  rows: ReadinessRow[];
}) {
  return (
    <Card className="p-5">
      <h2 className="text-ep-xl font-semibold mb-3">Readiness before starting a UE</h2>
      <ul className="flex flex-col gap-2.5 text-ep-md">
        {rows.map((r) => (
          <li key={r.label} className="flex items-center justify-between gap-3">
            <span>{r.label}</span>
            {r.status === 'pass' ? (
              <Pill tone="ok">PASS</Pill>
            ) : r.status === 'warn' ? (
              <Pill tone="warn">{r.detail ?? 'ATTENTION'}</Pill>
            ) : (
              <Pill tone="bad">{r.detail ?? 'FAIL'}</Pill>
            )}
          </li>
        ))}
      </ul>
    </Card>
  );
}

function RecentActivity({
  items,
}: {
  items: { who: string; what: string }[];
}) {
  return (
    <Card className="p-5">
      <h2 className="text-ep-xl font-semibold mb-3">Recent activity</h2>
      {items.length === 0 ? (
        <p className="text-ep-md text-mute">No recent event. Run a scenario or start a UE.</p>
      ) : (
        <ul className="flex flex-col divide-y divide-line text-ep-md">
          {items.map((it, i) => (
            <li key={i} className="py-2.5 flex gap-3">
              <span className="mono w-28 shrink-0">{it.who}</span>
              <span className="text-mute">{it.what}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function Stat({
  label,
  value,
  sub,
}: {
  label: string;
  value: string;
  sub?: string;
}) {
  return (
    <Card className="p-4 flex flex-col gap-1">
      <p className="text-ep-xs font-semibold uppercase tracking-wider text-mute">{label}</p>
      <p className="num text-[26px] leading-tight font-medium">{value}</p>
      {sub ? <p className="text-ep-sm text-mute">{sub}</p> : null}
    </Card>
  );
}

export function ConsolePage() {
  const lab = useLab();
  const observedLab = useLabObserved();
  const ues = useUes();
  const nodes = useNodes();
  const runtime = useScenarioRuntime();
  const history = useScenarioHistory();
  const health = useSystemHealth();

  const loading = lab.isLoading && ues.isLoading && nodes.isLoading;
  const error = lab.error || ues.error;

  const nfValues = Object.values(observedLab.data?.observed?.nfs ?? {});
  const observedNfs = nfValues.filter((nf) => nf.observed).length;
  const healthyNfs = nfValues.filter((nf) =>
    nf.observed && nf.process_state === 'running' && nf.health === 'healthy').length;
  const coreFunctions = nfValues.length > 0 ? `${healthyNfs} / ${observedNfs}` : 'UNKNOWN';

  // gNodeBs — count ACTIVE (running) ones vs planned, from /nodes
  const nodeList = (nodes.data?.items ?? []).filter((n) =>
    n.technology.includes('5G') || n.technology === 'NR',
  );
  const activeGnbs = nodeList.filter((n) => n.process_state === 'running').length;
  const plannedGnbs = nodeList.length - activeGnbs;

  // UEs & PDU
  const registered = ues.data?.registered_count ?? 0;
  const configuredUes = ues.data?.configured_count ?? 0;
  const liveCap = lab.data?.max_ues ?? configuredUes;
  const pdu = ues.data?.pdu_session_count ?? 0;
  const diskView = diskMeasurementView(health.data, health.error as Error | null);

  // Readiness
  const missingSubscribers = lab.data?.missing_subscriber_profiles ?? 0;
  const readinessRows: ReadinessRow[] = [
    { label: 'Serving gNB is active', status: activeGnbs > 0 ? 'pass' : 'warn', detail: activeGnbs === 0 ? 'No active gNB' : undefined },
    { label: 'PLMN matches UE, gNB and AMF', status: 'warn', detail: NOT_AVAILABLE },
    { label: 'gNB TAC is in the AMF TAI list', status: 'warn', detail: NOT_AVAILABLE },
    { label: 'UE S-NSSAI served by AMF and SMF', status: 'warn', detail: NOT_AVAILABLE },
    {
      label: 'Subscriber provisioned in Open5GS',
      status: missingSubscribers === 0 ? 'pass' : 'warn',
      detail:
        missingSubscribers > 0
          ? `${missingSubscribers} profile${missingSubscribers > 1 ? 's' : ''} not provisioned`
          : undefined,
    },
  ];

  // Recent activity: last 4 scenario jobs + current one if any
  const activeJob = runtime.data?.active_job;
  const hist = history.data?.items ?? [];
  const activityItems: { who: string; what: string }[] = [];
  if (activeJob) {
    activityItems.push({
      who: activeJob.target_ue_id ?? 'scenario',
      what: `${activeJob.scenario_id} · ${activeJob.state}`,
    });
  }
  for (const item of hist.slice(0, 4 - activityItems.length)) {
    activityItems.push({
      who: item.target_ue_id ?? 'scenario',
      what: `${item.scenario_id} · ${item.terminal_result ?? item.state}`,
    });
  }

  return (
    <>
      <PageHeader
        eyebrow="Network"
        title="Console"
        desc="One view of the simulated network: core, radio and the UEs running on it."
      />

      {loading && !lab.data && <LoadingSkeleton label="Loading lab state" />}
      {error && !loading && (
        <ErrorState
          title="Could not load POLARIS console"
          detail={(error as Error).message}
          onRetry={() => {
            void lab.refetch();
            void ues.refetch();
            void nodes.refetch();
          }}
        />
      )}

      {!loading && !error && (
        <>
          <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
            <Stat
              label="Core functions"
              value={coreFunctions}
              sub="Open5GS · observed containers only"
            />
            <Stat
              label="gNodeBs"
              value={`${activeGnbs} active`}
              sub={plannedGnbs > 0 ? `${plannedGnbs} planned` : 'no planned'}
            />
            <Stat
              label="UEs registered"
              value={String(registered)}
              sub={`of ${configuredUes} profiles · live cap ${liveCap}`}
            />
            <Stat
              label="PDU sessions"
              value={String(pdu)}
              sub={`DNN ${NOT_AVAILABLE}`}
            />
          </div>
          <Card className="p-4" data-testid="disk-measurement">
            <p className="text-ep-xs font-semibold uppercase tracking-wider text-mute">Disque</p>
            {diskView.error ? (
              <div className="mt-2 text-bad" role="alert" data-testid="disk-measurement-error">
                <strong>Erreur de mesure disque</strong>
                <p className="text-ep-sm">{diskView.error}</p>
              </div>
            ) : (
              <div className="mt-2" data-testid="disk-measurement-ok">
                <strong className="num">{diskView.usage}</strong>
                <p className="text-ep-sm text-mute">
                  {health.data?.decision.writes_allowed
                    ? 'Mesure valide · nouveaux jobs autorisés'
                    : `Nouveaux jobs bloqués · ${health.data?.decision.reason ?? 'raison non rapportée'}`}
                </p>
              </div>
            )}
          </Card>
          <div className="grid gap-5 lg:grid-cols-2">
            <Readiness rows={readinessRows} />
            <RecentActivity items={activityItems} />
          </div>
        </>
      )}
    </>
  );
}
