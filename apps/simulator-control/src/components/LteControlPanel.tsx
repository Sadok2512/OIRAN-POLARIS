import { Play, Square } from 'lucide-react';
import { Btn, Card, Pill, regTone } from '@/components/mockup';
import { useAuth, useLteAction, useLteLogs, useLteProfile, useLteStatus } from '@/data/queries';

export function LteControlPanel({ compact = false }: { compact?: boolean }) {
  const auth = useAuth();
  const status = useLteStatus();
  const stop = useLteAction('stop');
  const profile = useLteProfile();
  const enbLogs = useLteLogs('ENB-01');
  const ueLogs = useLteLogs('LTE-SRSUE-TEST-01');
  const data = status.data;
  const canOperate = auth.data?.can_start === true;
  const liveReady = data?.certified === true && data.live_enabled === true;
  const ueRunning = data?.ue.process_state === 'running';
  const enbRunning = data?.enb.process_state === 'running';
  const error = stop.error;

  return (
    <Card className="p-5 flex flex-col gap-4" data-testid="lte-control-panel">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-ep-xl font-semibold">LTE 4G — srsRAN</h2>
          <p className="text-ep-sm text-mute">
            Existing POLARIS controller · live stays locked until ANR1 E2E certification.
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
        <div><dt className="text-ep-xs uppercase text-mute">UE</dt><dd className="mono">{data?.ue_id ?? 'LTE-SRSUE-TEST-01'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">srsUE</dt><dd>{data?.ue.process_state ?? 'NOT OBSERVED'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">srsENB</dt><dd>{data?.enb.process_state ?? 'NOT OBSERVED'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">EPC / S1</dt><dd>{data?.epc.process_state ?? 'NOT OBSERVED'} / {data?.s1_state ?? 'NOT OBSERVED'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Attach</dt><dd>{data?.attach_state ?? 'NOT OBSERVED'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">APN</dt><dd className="mono">{data?.apn ?? 'internet'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">UE IP</dt><dd className="mono">{data?.ue_ip ?? 'NOT OBSERVED'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Sessions</dt><dd>{data?.active_sessions ?? 0}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Simulator</dt><dd>srsRAN</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Technology</dt><dd>LTE 4G</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Grant contract</dt><dd>{profile.data?.grant_required ? 'V2 REQUIRED' : 'NOT OBSERVED'}</dd></div>
      </dl>

      <div className="flex flex-wrap gap-2 border-t border-line pt-3">
        <Btn
          icon={Play}
          disabled
          title="Start is available only through a consumed LTE Grant V2 run."
          data-testid="lte-enb-start"
        >Start srsENB</Btn>
        <Btn
          icon={Play}
          primary
          disabled
          title="Start is available only through POST /api/v1/lte/runs with a one-time Grant V2 nonce."
          data-testid="lte-ue-start"
        >Start srsUE</Btn>
        <Btn
          icon={Square}
          onClick={() => stop.mutate('LTE-SRSUE-TEST-01')}
          disabled={!canOperate || !ueRunning || stop.isPending}
          data-testid="lte-ue-stop"
        >Stop srsUE</Btn>
        <Btn
          icon={Square}
          onClick={() => stop.mutate('ENB-01')}
          disabled={!canOperate || !enbRunning || ueRunning || stop.isPending}
          title={ueRunning ? 'Stop srsUE before srsENB.' : undefined}
          data-testid="lte-enb-stop"
        >Stop srsENB</Btn>
      </div>

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
