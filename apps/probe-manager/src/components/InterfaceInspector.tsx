import type {
  Capture,
  CaptureInterface,
  Metrics,
  Probe,
} from '@shared/types';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { EmptyState } from '@/ui/EmptyErrorLoading';
import { bytes, count, pps, isoToLocal } from '@/data/format';

export function InterfaceInspector({
  iface,
  probes,
  metrics,
  captures,
}: {
  iface: CaptureInterface | null;
  probes?: Probe[];
  metrics?: Metrics;
  captures?: Capture[];
}) {
  if (!iface) {
    return (
      <EmptyState
        title="Select an interface"
        description="Click a row to inspect the mapped probe, live counters and linked capture jobs."
      />
    );
  }

  const linkedProbe = probes?.find((probe) =>
    probe.connected_interfaces.includes(iface.interface),
  );
  const liveRate = metrics?.interfaces.find(
    (entry) => entry.interface === iface.interface,
  );
  const linkedCaptures =
    captures?.filter(
      (capture) =>
        capture.interface === iface.interface ||
        (capture.interfaces?.includes(iface.interface) ?? false) ||
        (capture.planes?.some((plane) => plane.interface === iface.interface) ??
          false),
    ) ?? [];

  return (
    <aside
      className="ep-card p-4 flex flex-col gap-4 sticky top-5 self-start min-w-0"
      aria-label="Interface inspector"
      data-testid="interface-inspector"
    >
      <header>
        <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
          Inspector
        </p>
        <h2 className="text-ep-lg font-semibold">{iface.interface}</h2>
        <p className="text-ep-xs text-text-secondary">{iface.capture_point}</p>
      </header>

      <dl className="grid grid-cols-2 gap-x-5 gap-y-1 text-ep-sm">
        <dt className="text-text-secondary">Linux device</dt>
        <dd className="mono text-ep-xs break-all">{iface.device ?? '—'}</dd>
        <dt className="text-text-secondary">Protocol</dt>
        <dd>{iface.protocol}</dd>
        <dt className="text-text-secondary">UP/DOWN</dt>
        <dd>
          <StatusIndicator state={iface.status} compact />
        </dd>
        <dt className="text-text-secondary">Live capture visibility</dt>
        <dd>
          <StatusIndicator
            state={iface.live_capture_available ? 'AUTHORIZED' : 'GATED'}
            compact
          />
        </dd>
        <dt className="text-text-secondary">Linked probe</dt>
        <dd>{linkedProbe?.name ?? 'Unmapped'}</dd>
        <dt className="text-text-secondary">Reason</dt>
        <dd className="break-words">{iface.reason ?? '—'}</dd>
      </dl>

      <section>
        <h3 className="text-ep-sm font-semibold mb-1">Live counters</h3>
        <dl className="grid grid-cols-2 gap-x-5 gap-y-1 text-ep-sm">
          <dt className="text-text-secondary">Packet rate</dt>
          <dd className="num">{pps(liveRate?.packet_rate_pps)}</dd>
          <dt className="text-text-secondary">Interface state</dt>
          <dd>
            <StatusIndicator state={liveRate?.state ?? iface.status} compact />
          </dd>
          <dt className="text-text-secondary">Last capture start</dt>
          <dd>{isoToLocal(iface.capture_start)}</dd>
          <dt className="text-text-secondary">Last capture end</dt>
          <dd>{isoToLocal(iface.capture_end)}</dd>
          <dt className="text-text-secondary">Historical packets</dt>
          <dd className="num">{count(iface.packet_count)}</dd>
          <dt className="text-text-secondary">Historical bytes</dt>
          <dd className="num">{bytes(iface.file_size)}</dd>
        </dl>
      </section>

      <section>
        <h3 className="text-ep-sm font-semibold mb-1">
          Linked capture jobs · {count(linkedCaptures.length)}
        </h3>
        {!linkedCaptures.length ? (
          <p className="text-ep-xs text-text-secondary">
            No capture jobs reference this interface.
          </p>
        ) : (
          <ul className="flex flex-col gap-1 text-ep-xs">
            {linkedCaptures.slice(0, 6).map((capture) => (
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
          </ul>
        )}
      </section>
    </aside>
  );
}
