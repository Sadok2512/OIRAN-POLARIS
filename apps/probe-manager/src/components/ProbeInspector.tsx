import type { Capture, CaptureInterface, Probe } from '@shared/types';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { EmptyState } from '@/ui/EmptyErrorLoading';
import { bytes, count, percent } from '@/data/format';
import { roleBadgeClass, roleForInterface } from '@/data/roleMapping';
import { formatHeartbeat, probeLifecycle, probeLifecycleTone } from '@/data/probeState';

export function ProbeInspector({
  probe,
  captures,
  interfaces,
}: {
  probe: Probe | null;
  captures?: Capture[];
  interfaces?: CaptureInterface[];
}) {
  if (!probe) {
    return (
      <EmptyState
        title="Select a probe"
        description="Pick a row from the table to inspect its endpoints, telemetry and capture jobs."
      />
    );
  }
  const probeCaptures =
    captures?.filter((capture) => capture.probe_id === probe.probe_id) ?? [];
  const active = probeCaptures.filter((capture) =>
    ['CAPTURING', 'STARTING', 'STOPPING', 'PROCESSING'].includes(
      capture.state ?? '',
    ),
  );
  const history = probeCaptures.filter(
    (capture) =>
      !['CAPTURING', 'STARTING', 'STOPPING', 'PROCESSING'].includes(
        capture.state ?? '',
      ),
  );

  // The backend returns `connected_interfaces` as string[] on Probe, and the
  // full CaptureInterface shape in `/interfaces`. Join them on the name so
  // the inspector surfaces protocol / capture_point / status / device from
  // real fields only — never fabricated.
  const connectedNames = new Set(probe.connected_interfaces);
  const detailedInterfaces = (interfaces ?? []).filter((item) =>
    connectedNames.has(item.interface),
  );

  return (
    <aside
      className="ep-card p-4 flex flex-col gap-4 sticky top-5 self-start min-w-0"
      aria-label="Probe inspector"
      data-testid="probe-inspector"
    >
      <header>
        <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
          Inspector
        </p>
        <h2 className="text-ep-lg font-semibold">{probe.name}</h2>
        <p className="mono text-ep-xs text-text-secondary break-all">
          {probe.probe_id}
        </p>
      </header>

      <dl className="grid grid-cols-2 gap-x-5 gap-y-1 text-ep-sm">
        <dt className="text-text-secondary">Type</dt>
        <dd>{probe.probe_type}</dd>
        <dt className="text-text-secondary">Version</dt>
        <dd>{probe.version || '—'}</dd>
        <dt className="text-text-secondary">Host / namespace</dt>
        <dd className="mono text-ep-xs break-all">{probe.host}</dd>
        <dt className="text-text-secondary">Last heartbeat</dt>
        <dd data-testid={`heartbeat-${probe.probe_id}`}>
          {formatHeartbeat(probe.last_heartbeat_epoch_s)}
        </dd>
        <dt className="text-text-secondary">Lifecycle</dt>
        <dd>
          {(() => {
            const lifecycle = probeLifecycle(probe);
            return (
              <StatusIndicator
                state={lifecycle}
                tone={probeLifecycleTone(lifecycle)}
                compact
              />
            );
          })()}
        </dd>
        <dt className="text-text-secondary">Capture state</dt>
        <dd>
          {probe.capture_state ? (
            <StatusIndicator state={probe.capture_state} compact />
          ) : (
            <span className="text-ep-xs text-text-secondary">—</span>
          )}
        </dd>
      </dl>

      <section>
        <h3 className="text-ep-sm font-semibold mb-1">Resource telemetry</h3>
        <dl className="grid grid-cols-3 gap-x-3 gap-y-1 text-ep-xs">
          <dt className="text-text-secondary">CPU</dt>
          <dt className="text-text-secondary">RAM</dt>
          <dt className="text-text-secondary">Disk</dt>
          <dd className="num">{percent(probe.cpu_usage_percent)}</dd>
          <dd className="num">{bytes(probe.memory_usage_bytes)}</dd>
          <dd className="num">{percent(probe.disk_usage_percent)}</dd>
        </dl>
      </section>

      <section>
        <h3 className="text-ep-sm font-semibold mb-1">
          Capture points · {count(probe.connected_interfaces.length)}
        </h3>
        {probe.connected_interfaces.length === 0 ? (
          <p className="text-ep-xs text-text-secondary">
            No capture points reported.
          </p>
        ) : detailedInterfaces.length === 0 ? (
          <ul className="flex flex-wrap gap-1.5" data-testid="probe-interface-chips">
            {probe.connected_interfaces.map((name) => (
              <li key={name}>
                <span className="ep-badge mono" title="Interface not resolved via /interfaces">
                  {name}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <ul className="flex flex-col gap-1 text-ep-xs" data-testid="probe-interface-list">
            {detailedInterfaces.map((item) => {
              const role = roleForInterface(item);
              return (
                <li
                  key={item.interface}
                  className="flex items-center justify-between gap-2 border border-border rounded-md px-2 py-1"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className={`ep-badge ${roleBadgeClass(role)}`}>{role ?? '—'}</span>
                    <span className="mono truncate">{item.interface}</span>
                    <span className="text-text-secondary">· {item.protocol}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="mono text-text-secondary">{item.device ?? '—'}</span>
                    <StatusIndicator state={item.status} compact />
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section>
        <h3 className="text-ep-sm font-semibold mb-1">
          Capture jobs · {count(probeCaptures.length)}
        </h3>
        {!probeCaptures.length ? (
          <p className="text-ep-xs text-text-secondary">
            No jobs reported for this probe.
          </p>
        ) : (
          <ul className="flex flex-col gap-1 text-ep-xs">
            {active.slice(0, 3).map((capture) => (
              <li
                key={capture.capture_id}
                className="flex items-center justify-between gap-2"
              >
                <span className="truncate" title={capture.name}>
                  {capture.name}
                </span>
                <StatusIndicator state={capture.state ?? 'UNKNOWN'} compact />
              </li>
            ))}
            {history.slice(0, 3).map((capture) => (
              <li
                key={capture.capture_id}
                className="flex items-center justify-between gap-2 text-text-secondary"
              >
                <span className="truncate" title={capture.name}>
                  {capture.name}
                </span>
                <StatusIndicator state={capture.state ?? 'UNKNOWN'} compact />
              </li>
            ))}
          </ul>
        )}
      </section>
    </aside>
  );
}
