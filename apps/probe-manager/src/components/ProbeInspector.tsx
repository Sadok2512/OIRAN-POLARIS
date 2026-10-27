import type { Capture, Probe } from '@shared/types';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { EmptyState } from '@/ui/EmptyErrorLoading';
import { bytes, count, percent, isoToLocal } from '@/data/format';

export function ProbeInspector({
  probe,
  captures,
}: {
  probe: Probe | null;
  captures?: Capture[];
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
        <dd>{isoToLocal(probe.last_heartbeat ?? undefined)}</dd>
        <dt className="text-text-secondary">Health</dt>
        <dd>
          <StatusIndicator state={probe.online ? 'ONLINE' : 'OFFLINE'} compact />
        </dd>
        <dt className="text-text-secondary">Capture state</dt>
        <dd>
          <StatusIndicator state={probe.capture_state} compact />
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
        <h3 className="text-ep-sm font-semibold mb-1">Capture points</h3>
        {probe.connected_interfaces.length ? (
          <ul className="flex flex-wrap gap-1.5">
            {probe.connected_interfaces.map((iface) => (
              <li key={iface}>
                <span className="ep-badge mono">{iface}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-ep-xs text-text-secondary">
            No capture points reported.
          </p>
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
