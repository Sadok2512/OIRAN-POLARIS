import { useMemo, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Plus, Search } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from '@/ui/EmptyErrorLoading';
import { ProbeInspector } from '@/components/ProbeInspector';
import { RegisterProbeDialog } from '@/components/RegisterProbeDialog';
import { useCaptures, useInterfaces, useProbes } from '@/data/queries';
import { bytes, count, percent } from '@/data/format';
import { roleBadgeClass, roleForInterface } from '@/data/roleMapping';
import type { CaptureInterface } from '@shared/types';

export function ProbesPage() {
  const probes = useProbes();
  const captures = useCaptures();
  const interfaces = useInterfaces();
  const { probeId } = useParams();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [registerOpen, setRegisterOpen] = useState(false);

  const interfacesByName = useMemo(() => {
    const map = new Map<string, CaptureInterface>();
    for (const item of interfaces.data ?? []) map.set(item.interface, item);
    return map;
  }, [interfaces.data]);

  const filtered = useMemo(
    () =>
      probes.data?.filter((probe) =>
        `${probe.name} ${probe.host} ${probe.probe_id} ${probe.connected_interfaces.join(' ')}`
          .toLowerCase()
          .includes(search.toLowerCase()),
      ) ?? [],
    [probes.data, search],
  );

  const selected =
    probes.data?.find((probe) => probe.probe_id === probeId) ??
    filtered[0] ??
    probes.data?.[0];

  return (
    <>
      <PageHeader
        eyebrow="Operations"
        title="Probes"
        description="Physical and virtual probes reported by the backend. No credentials are displayed; management endpoints are shown read-only."
        actions={
          <div className="flex items-center gap-2">
            <label className="relative">
              <Search
                className="absolute left-2 top-1/2 -translate-y-1/2 text-text-secondary"
                width={14}
                height={14}
                aria-hidden="true"
              />
              <input
                className="ep-input pl-7"
                placeholder="Search probes"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                aria-label="Search probes"
                data-testid="probe-search"
              />
            </label>
            <button
              type="button"
              className="ep-button ep-button-sm ep-button-primary"
              onClick={() => setRegisterOpen(true)}
              data-testid="register-probe-open"
            >
              <Plus width={13} height={13} /> Register probe
            </button>
          </div>
        }
      />

      {probes.isLoading && <LoadingSkeleton label="Loading probes" />}
      {probes.error && !probes.isLoading && (
        <ErrorState
          title="Could not load probes"
          detail={(probes.error as Error).message}
          onRetry={() => void probes.refetch()}
        />
      )}

      {!probes.isLoading && !probes.error && !filtered.length && (
        <EmptyState
          title="No probes match"
          description="Register a vProbe or clear the search to see the fleet."
        />
      )}

      {filtered.length > 0 && (
        <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_380px]">
          <div className="ep-card overflow-hidden">
            <table className="ep-table" data-testid="probe-table">
              <thead>
                <tr>
                  <th>Probe</th>
                  <th>Type</th>
                  <th>Host</th>
                  <th>Interfaces</th>
                  <th>Health</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((probe) => (
                  <tr
                    key={probe.probe_id}
                    onClick={() => navigate(`/probes/${probe.probe_id}`)}
                    data-selected={selected?.probe_id === probe.probe_id}
                    className="cursor-pointer"
                  >
                    <td>
                      <div className="flex flex-col">
                        <span className="font-medium">{probe.name}</span>
                        <span className="text-text-secondary mono text-ep-xs truncate">
                          {probe.probe_id}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className="ep-badge">{probe.probe_type}</span>
                    </td>
                    <td className="mono text-ep-xs">{probe.host}</td>
                    <td>
                      <div
                        className="flex flex-wrap items-center gap-1"
                        data-testid={`probe-row-chips-${probe.probe_id}`}
                      >
                        {probe.connected_interfaces.length === 0 && (
                          <span className="text-text-secondary text-ep-xs">—</span>
                        )}
                        {probe.connected_interfaces.map((name) => {
                          const item = interfacesByName.get(name);
                          const role = item ? roleForInterface(item) : null;
                          return (
                            <span
                              key={name}
                              className={`ep-badge ${roleBadgeClass(role)}`}
                              title={
                                item
                                  ? `${name} · ${item.protocol} · ${item.capture_point}`
                                  : `${name} · not resolved via /interfaces`
                              }
                            >
                              {role ?? '—'}
                              <span className="mono text-text-secondary">· {name}</span>
                            </span>
                          );
                        })}
                      </div>
                    </td>
                    <td>
                      <StatusIndicator
                        state={probe.online ? 'ONLINE' : 'OFFLINE'}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="px-3 py-2 border-t border-border text-ep-xs text-text-secondary flex gap-4">
              <span>
                CPU avg{' '}
                <span className="num text-text-primary">
                  {percent(
                    filtered
                      .map((probe) => probe.cpu_usage_percent)
                      .filter((v): v is number => v != null)
                      .reduce(
                        (acc, v, _, arr) => acc + v / Math.max(1, arr.length),
                        0,
                      ),
                  )}
                </span>
              </span>
              <span>
                Memory used total{' '}
                <span className="num text-text-primary">
                  {bytes(
                    filtered
                      .map((probe) => probe.memory_usage_bytes)
                      .filter((v): v is number => v != null)
                      .reduce((acc, v) => acc + v, 0),
                  )}
                </span>
              </span>
              <span className="num">
                {count(filtered.length)} probe{filtered.length === 1 ? '' : 's'}
              </span>
            </div>
          </div>
          <ProbeInspector
            probe={selected ?? null}
            captures={captures.data?.items}
            interfaces={interfaces.data}
          />
        </div>
      )}

      <RegisterProbeDialog open={registerOpen} onClose={() => setRegisterOpen(false)} />
    </>
  );
}
