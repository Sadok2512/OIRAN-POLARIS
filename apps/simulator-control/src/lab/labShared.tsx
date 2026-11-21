// 0.36.0 — Shared helpers for the simplified « Lab » pages (UE list,
// UE monitoring, scenarios) built from the user's mockup
// (polaris-workflow-prototype.html). Light on purpose: few queries, no
// heavy tables, every value comes from the API or shows « -- (raison) ».

import clsx from 'clsx';
import type { ReactNode } from 'react';
import type { WireScenarioDefinition, WireScenarioStep } from '@/scenarios/wireCodec';

export type Tone = 'ok' | 'warn' | 'bad' | 'run' | 'idle';

export function Badge({ tone, children, pulse }: { tone: Tone; children: ReactNode; pulse?: boolean }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-ep-xs font-semibold whitespace-nowrap',
        tone === 'ok' && 'bg-ok-soft text-ok',
        tone === 'warn' && 'bg-warn-soft text-warn',
        tone === 'bad' && 'bg-bad-soft text-bad',
        tone === 'run' && 'bg-brand-soft text-brand',
        tone === 'idle' && 'bg-track text-mute',
      )}
    >
      {pulse && <span className="h-2 w-2 rounded-full bg-current animate-pulse" aria-hidden="true" />}
      {children}
    </span>
  );
}

export function Kpi({ label, value, sub, testid }: { label: string; value: ReactNode; sub?: ReactNode; testid?: string }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-3.5 flex flex-col gap-1" data-testid={testid}>
      <span className="text-ep-xs text-mute">{label}</span>
      <strong className="text-ep-lg text-ink">{value}</strong>
      {sub != null && <span className="text-ep-xs text-mute">{sub}</span>}
    </div>
  );
}

/** French label for a backend reason code; the code stays visible for engineers. */
export function reasonFr(code: string | null | undefined): string {
  if (!code) return '';
  const map: Record<string, string> = {
    SHARED_UE_PROTECTED: 'UE partagé protégé (non pilotable)',
    LTE_E2E_CERTIFICATION_REQUIRED: 'LTE : certification requise',
    UE_CONTROL_VALIDATION_REQUIRED: 'Autorisation live demandée au lancement',
    UE_NOT_RUNNING: 'UE arrêté',
    SUBSCRIBER_NOT_PROVISIONED: 'Abonné absent d’Open5GS',
    GNB_STOPPED_CONTEXT_AMBIGUOUS:
      'Arrêt incomplet : demande à un agent lab de redémarrer le gNB quand aucun UE n’est actif',
  };
  return map[code] ? `${map[code]} · ${code}` : code;
}

/** Scenario needs two UEs (voice call) → not runnable from a single UE row. */
export function needsTwoUes(def: Pick<WireScenarioDefinition, 'steps'>): boolean {
  const walk = (steps: WireScenarioStep[]): boolean =>
    steps.some((s) => s.type === 'voice_call' || (s.steps ? walk(s.steps) : false));
  return walk(def.steps ?? []);
}

const STEP_FR: Record<string, string> = {
  ue_start: 'Démarrer l’UE',
  pdu_establish: 'PDU',
  traffic_dl: 'Trafic DL',
  traffic_ul: 'Trafic UL',
  transfer_verify: 'Vérif. transfert',
  ims_register: 'REGISTER IMS',
  voice_call: 'Appel voix',
  wait: 'Attente',
  idle: 'Pause',
  detach: 'Détacher',
  ue_stop: 'Arrêter l’UE',
  repeat: 'Répéter',
  lte_attach: 'Attach LTE',
  lte_detach: 'Detach LTE',
};

function fixed(step: WireScenarioStep, key: string): unknown {
  const p = step.parameters?.[key] as { fixed?: unknown } | undefined;
  return p && typeof p === 'object' ? p.fixed : undefined;
}

export function stepLabel(step: WireScenarioStep): string {
  const base = STEP_FR[step.type] ?? step.type;
  if (step.type === 'pdu_establish') {
    const dnn = fixed(step, 'dnn');
    return typeof dnn === 'string' ? `PDU ${dnn}` : base;
  }
  if (step.type === 'traffic_dl' || step.type === 'traffic_ul') {
    const bytes = fixed(step, 'bytes');
    return typeof bytes === 'number' ? `${base} ${formatBytes(bytes)}` : base;
  }
  if (step.type === 'repeat') {
    const inner = (step.steps ?? []).map(stepLabel).join(' → ');
    return `${step.loop_count}× (${inner})`;
  }
  return base;
}

export function stepsSummary(def: Pick<WireScenarioDefinition, 'steps'>): string {
  return (def.steps ?? []).map(stepLabel).join(' → ');
}

export function formatBytes(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return '--';
  if (n >= 1024 * 1024 * 1024) return `${(n / 1024 / 1024 / 1024).toFixed(1)} Go`;
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} Mo`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} ko`;
  return `${n} o`;
}

export function formatBps(bps: number | null | undefined): string {
  if (bps == null || !Number.isFinite(bps)) return '--';
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbit/s`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} kbit/s`;
  return `${Math.round(bps)} bit/s`;
}

export function hhmmss(epochS: number | null | undefined): string {
  if (epochS == null) return '--';
  return new Date(epochS * 1000).toISOString().slice(11, 19);
}

/** One sample of the throughput chart. */
export interface RateSample {
  dl: number;
  ul: number;
}

export function ThroughputChart({ samples, testid }: { samples: RateSample[]; testid?: string }) {
  const w = 560;
  const h = 200;
  const pad = 36;
  const max = Math.max(1, ...samples.map((s) => Math.max(s.dl, s.ul)));
  const n = Math.max(2, samples.length);
  const pts = (key: keyof RateSample) =>
    samples
      .map((s, i) => `${(pad + (i * (w - pad - 8)) / (n - 1)).toFixed(1)},${(h - 20 - (s[key] / max) * (h - 40)).toFixed(1)}`)
      .join(' ');
  return (
    <figure className="m-0" data-testid={testid}>
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" role="img" aria-label="Débit DL et UL en direct">
        <line x1={pad} y1={h - 20} x2={w - 8} y2={h - 20} stroke="var(--c-border)" />
        <line x1={pad} y1={12} x2={pad} y2={h - 20} stroke="var(--c-border)" />
        <text x={4} y={20} fontSize="11" fill="var(--c-text-secondary)">{formatBps(max)}</text>
        <text x={4} y={h - 16} fontSize="11" fill="var(--c-text-secondary)">0</text>
        {samples.length > 0 && (
          <>
            <polyline points={pts('dl')} fill="none" stroke="var(--c-primary)" strokeWidth="2.5" />
            <polyline points={pts('ul')} fill="none" stroke="var(--c-warning)" strokeWidth="2.5" />
          </>
        )}
      </svg>
      <figcaption className="flex gap-4 text-ep-xs text-mute">
        <span><span className="text-brand">━</span> DL</span>
        <span><span className="text-warn">━</span> UL</span>
        {samples.length === 0 && <span>-- (aucun échantillon : UE arrêté ou sans trafic)</span>}
      </figcaption>
    </figure>
  );
}
