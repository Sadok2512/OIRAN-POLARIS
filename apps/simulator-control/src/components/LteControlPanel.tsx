import { useEffect, useState } from 'react';
import { Play, Square } from 'lucide-react';
import { Btn, Card, Pill, regTone } from '@/components/mockup';
import { useAuth, useLteAction, useLteLogs, useLteProfile, useLteStatus } from '@/data/queries';
import { formatCountdown, useActivateLteCertification, useEmergencyStopLteRun, useLteRun, usePrepareLteCertificationGrant, useStartLteCertifiedRun } from '@/data/liveGrantApi';

export function LteControlPanel({ compact = false }: { compact?: boolean }) {
  const auth = useAuth();
  const status = useLteStatus();
  const stop = useLteAction('stop');
  const prepareGrant = usePrepareLteCertificationGrant();
  const activateCertification = useActivateLteCertification();
  const startRun = useStartLteCertifiedRun();
  const run = useLteRun(startRun.data?.run_id);
  const emergencyStop = useEmergencyStopLteRun();
  const profile = useLteProfile();
  const enbLogs = useLteLogs('ENB-01');
  const ueLogs = useLteLogs('LTE-SRSUE-TEST-01');
  const data = status.data;
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, []);
  const canOperate = auth.data?.can_start === true;
  const certificationMode = data?.operation_mode === 'CERTIFICATION_RUN';
  const operationalMode = data?.operation_mode === 'LIVE_OPERATIONAL';
  const baseGateReady = (certificationMode || operationalMode)
    && data.live_enabled === true
    && data.safety_ready === true
    && typeof profile.data?.compose_model_sha256 === 'string'
    && data.grant_active !== true;
  const preparedGrantValid = Boolean(
    prepareGrant.data
    && prepareGrant.data.grant.purpose === 'CERTIFICATION_RUN'
    && prepareGrant.data.grant.state === 'ISSUED'
    && prepareGrant.data.grant.expires_at_epoch_ms > now,
  );
  const temporaryActivationValid = Boolean(
    profile.data?.temporary_activation_active
    && profile.data.temporary_activation_expires_at_epoch_ms
    && profile.data.temporary_activation_expires_at_epoch_ms > now
    && profile.data.temporary_activation_grant_id === prepareGrant.data?.grant.grant_id,
  );
  const startGateReady = baseGateReady && (certificationMode
    ? temporaryActivationValid
    : profile.data?.permanent_enabled === true);
  const ownershipVerified = data?.ownership_verified === true;
  const ueRunning = data?.ue.process_state === 'running';
  const enbRunning = data?.enb.process_state === 'running';
  const certificationState = data?.certification_state ?? 'CERTIFICATION_PENDING';
  const statusLabel = certificationState.replaceAll('_', ' ');
  const activationExpiry = profile.data?.temporary_activation_expires_at_epoch_ms ?? null;
  const activationCountdown = activationExpiry ? formatCountdown(activationExpiry, now) : '00:00';
  const error = stop.error ?? prepareGrant.error ?? activateCertification.error ?? startRun.error ?? emergencyStop.error;
  const binding = profile.data?.compose_model_sha256 ? {
    purpose: certificationMode ? 'CERTIFICATION_RUN' as const : 'LIVE_OPERATIONAL' as const,
    revision: profile.data.revision,
    configuration_sha256: profile.data.configuration_sha256,
    compose_model_sha256: profile.data.compose_model_sha256,
    scenario_id: profile.data.scenario_id,
    scenario_revision: profile.data.scenario_revision,
    scenario_sha256: profile.data.scenario_sha256,
  } : null;

  return (
    <Card className="p-5 flex flex-col gap-4" data-testid="lte-control-panel">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-ep-xl font-semibold">LTE 4G — srsRAN</h2>
          <p className="text-ep-sm text-mute">
            Certification runs are bounded and never promote themselves to operational certification.
          </p>
        </div>
        <div className="flex gap-2">
          <Pill tone={certificationState === 'CERTIFIED' ? 'ok' : certificationState === 'CERTIFICATION_FAILED' ? 'bad' : 'warn'}>
            <span data-testid="lte-certification-state">{statusLabel}</span>
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
        <div><dt className="text-ep-xs uppercase text-mute">APN</dt><dd className="mono">{data?.apn ?? 'NOT AVAILABLE'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">UE IP</dt><dd className="mono">{data?.ue_ip ?? 'NOT OBSERVED'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Sessions</dt><dd>{data?.session_state ?? 'UNKNOWN'} ({data?.active_sessions ?? 0})</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Simulator</dt><dd>srsRAN</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Technology</dt><dd>LTE 4G</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Grant contract</dt><dd>{profile.data?.grant_required ? 'V2 REQUIRED' : 'NOT OBSERVED'}</dd></div>
        <div><dt className="text-ep-xs uppercase text-mute">Activation Operator</dt><dd data-testid="lte-temp-activation-state">{profile.data?.temporary_activation_state ?? 'INACTIVE'} · {activationCountdown}</dd></div>
      </dl>

      <div className="flex flex-wrap gap-2 border-t border-line pt-3">
        {certificationMode ? <>
          <Btn
            disabled={!canOperate || !baseGateReady || !binding || preparedGrantValid || prepareGrant.isPending || profile.data?.temporary_activation_active}
            title="Crée un Grant V2 exact, borné à un UE et 300 secondes. Aucun simulateur n'est démarré."
            onClick={() => { if (binding) prepareGrant.mutate(binding); }}
            data-testid="lte-prepare-grant"
          >{prepareGrant.isPending ? 'Préparation…' : 'Préparer Grant V2 LTE'}</Btn>
          <Btn
            primary
            disabled={!canOperate || !preparedGrantValid || activateCertification.isPending || profile.data?.temporary_activation_active}
            title={preparedGrantValid ? 'Activation temporaire liée au Grant V2 exact.' : 'Un Grant V2 Certification Run valide est requis.'}
            onClick={() => { if (prepareGrant.data) activateCertification.mutate({ authorization: prepareGrant.data }); }}
            data-testid="lte-authorize-certification"
          >{activateCertification.isPending ? 'Autorisation…' : 'Autoriser certification LTE'}</Btn>
        </> : null}
        <Btn
          icon={Play}
          primary
          disabled={!canOperate || !startGateReady || startRun.isPending}
          title={startGateReady ? 'Consomme le Grant V2 lié à l’activation temporaire.' : 'Requires the exact mode, controller-owned profile, certified digests, safety gates and temporary Operator activation.'}
          onClick={() => {
            if (binding) {
              startRun.mutate({
                profile: binding,
                authorization: certificationMode ? prepareGrant.data : undefined,
              });
            }
          }}
          data-testid="lte-enb-start"
        >{startRun.isPending ? 'Starting bounded run…' : certificationMode ? 'Start LTE certification run' : 'Start LTE operational run'}</Btn>
        {run.data && run.data.state !== 'CLEAN' ? (
          <Btn
            icon={Square}
            onClick={() => emergencyStop.mutate(run.data!.run_id)}
            disabled={!canOperate || emergencyStop.isPending}
            data-testid="lte-emergency-stop"
          >Emergency stop / cleanup</Btn>
        ) : null}
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
