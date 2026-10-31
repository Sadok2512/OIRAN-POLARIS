import { Play, Square } from 'lucide-react';
import { Btn, Card, Pill, regTone } from '@/components/mockup';
import { useAuth, useLteAction, useLteLogs, useLteProfile, useLteStatus } from '@/data/queries';
import { useLteRun, useStartLteCertifiedRun } from '@/data/liveGrantApi';

export function LteControlPanel({ compact = false }: { compact?: boolean }) {
  const auth = useAuth();
  const status = useLteStatus();
  const stop = useLteAction('stop');
  const startRun = useStartLteCertifiedRun();
  const run = useLteRun(startRun.data?.run_id);
  const profile = useLteProfile();
  const enbLogs = useLteLogs('ENB-01');
  const ueLogs = useLteLogs('LTE-SRSUE-TEST-01');
  const data = status.data;
  const canOperate = auth.data?.can_start === true;
  const liveReady = data?.certified === true && data.live_enabled === true && data.grant_active === true && data.safety_ready === true;
  const startGateReady = data?.certified === true
    && data.live_enabled === true
    && data.safety_ready === true
    && profile.data?.enabled === true
    && data.grant_active !== true;
  const ownershipVerified = data?.ownership_verified === true;
  const ueRunning = data?.ue.process_state === 'running';
  const enbRunning = data?.enb.process_state === 'running';
  const error = stop.error ?? startRun.error;

  return (
    <Card className="p-5 flex flex-col gap-4" data-testid="lte-control-panel">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-ep-xl font-semibold">LTE 4G — srsRAN</h2>
          <p className="text-ep-sm text-mute">
            POLARIS-controlled srsRAN runtime · live actions remain protected by Grant V2 and certification gates.
          </p>
        </div>
        <div className="flex gap-2">
          <Pill tone={liveReady ? 'ok' : 'warn'}>
            {liveReady ? 'LIVE CERTIFIED' : 'CERTIFICATION REQUIRED'}
          </Pill>
          <Pill tone={regTone(data?.attach_state ?? 'UNKNOWN')}>{data?.attach_state ?? 'UNKNOWN'}</Pill>
        </div>
      </header>

      <dl className={`grid gap-3 text-ep-md ${compact ? 'grid-cols-2 lg:grid-cols-4' : 'grid-cols-2 lg:grid-cols-5'}`}>
        <div><dt className="text-ep-xs uppercase text-mute">UE</dt><dd className="mono">{data?.ue_id ?? 'NOT_AVAILABLE'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">srsUE</dt><dd>{data?.ue.process_state ?? 'NOT_AVAILABLE'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">srsENB</dt><dd>{data?.enb.process_state ?? 'NOT_AVAILABLE'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">EPC / S1</dt><dd>{data?.epc.process_state ?? 'NOT_AVAILABLE'} / {data?.s1_state ?? 'NOT_AVAILABLE'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Attach</dt><dd>{data?.attach_state ?? 'UNKNOWN'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">APN</dt><dd className="mono">{data?.apn ?? 'NOT_AVAILABLE'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">UE IP</dt><dd className="mono">{data?.ue_ip ?? 'NOT_AVAILABLE'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Sessions</dt><dd>{data ? `${data.session_state} (${data.active_sessions})` : 'NOT_AVAILABLE'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Simulator</dt><dd>srsRAN</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Technology</dt><dd>LTE 4G</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Grant contract</dt><dd>{profile.data?.grant_required ? 'V2 REQUIRED' : 'NOT OBSERVED'}</dd></div>
      </dl>

      <div className="flex flex-wrap gap-2 border-t border-line pt-3">
        <Btn
          icon={Play}
          primary
          disabled={!canOperate || !startGateReady || startRun.isPending}
          title={startGateReady ? 'Issues and consumes a one-time, five-minute LTE Grant V2.' : 'Requires ANR1 certification, enabled LTE profile, safety gates and no active LTE run.'}
          onClick={() => {
            if (profile.data) startRun.mutate(profile.data);
          }}
          data-testid="lte-enb-start"
        >{startRun.isPending ? 'Starting certified run…' : 'Start LTE certified run'}</Btn>
        <Btn
          icon={Square}
          onClick={() => stop.mutate('LTE-SRSUE-TEST-01')}
          disabled={!canOperate || !ueRunning || !data?.ue.controller_owned || stop.isPending}
          data-testid="lte-ue-stop"
        >Stop srsUE</Btn>
        <Btn
          icon={Square}
          onClick={() => stop.mutate('ENB-01')}
          disabled={!canOperate || !enbRunning || !data?.enb.controller_owned || ueRunning || stop.isPending}
          title={ueRunning ? 'Stop srsUE before srsENB.' : undefined}
          data-testid="lte-enb-stop"
        >Stop srsENB</Btn>
      </div>
      {!ownershipVerified && (enbRunning || ueRunning) ? <p className="text-ep-sm text-bad">Running srsRAN service is not controller-owned; lifecycle actions are locked.</p> : null}

      {run.data ? (
        <section className="rounded-md border border-line bg-surface-2 p-3" aria-label="LTE certified run progress">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-ep-sm font-medium">Certified run</span>
            <Pill tone={run.data.state === 'CLEAN' && run.data.final_state === 'COMPLETED' ? 'ok' : 'warn'}>{run.data.state}</Pill>
          </div>
          <ol className="mt-2 grid gap-1 text-ep-xs sm:grid-cols-2 lg:grid-cols-3">
            {(run.data.steps ?? []).map((step) => <li key={step.index}>{step.type}: {step.state}{step.reason_code ? ` — ${step.reason_code}` : ''}</li>)}
          </ol>
          {run.data.cleanup_required ? <p className="mt-2 text-ep-xs text-warn">Cleanup required; traffic will not resume.</p> : null}
        </section>
      ) : null}

      {error ? <p className="text-ep-sm text-bad">{(error as Error).message}</p> : null}
      {!compact ? (
        <details>
          <summary className="cursor-pointer text-ep-sm font-medium">Sanitized srsRAN logs and errors</summary>
          <pre className="mt-2 max-h-48 overflow-auto rounded-md bg-surface-2 p-3 text-ep-xs">
            {[...(enbLogs.data?.lines ?? []), ...(ueLogs.data?.lines ?? [])].slice(-16).join('\n') || 'No observed logs.'}
          </pre>
        </details>
      ) : null}
    </Card>
  );
}
