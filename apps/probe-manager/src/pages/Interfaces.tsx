import { useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Search } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from '@/ui/EmptyErrorLoading';
import { InterfaceInspector } from '@/components/InterfaceInspector';
import {
  useCaptures,
  useInterfaces,
  useMetrics,
  useProbes,
} from '@/data/queries';
import { bytes, count } from '@/data/format';

export function InterfacesPage() {
  const interfaces = useInterfaces();
  const probes = useProbes();
  const metrics = useMetrics();
  const captures = useCaptures();
  const { interfaceId } = useParams();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');

  const filtered = useMemo(
    () =>
      interfaces.data?.filter((item) =>
        `${item.interface} ${item.device ?? ''} ${item.protocol} ${item.capture_point}`
          .toLowerCase()
          .includes(search.toLowerCase()),
      ) ?? [],
    [interfaces.data, search],
  );

  const selected =
    interfaces.data?.find(
      (item) => item.interface === interfaceId || item.device === interfaceId,
    ) ??
    filtered[0] ??
    interfaces.data?.[0] ??
    null;

  return (
    <>
      <PageHeader
        eyebrow="Operations"
        title="Interfaces"
        description="Logical capture points reported by the backend, mapped to real Linux interfaces when the probe exposes them."
        actions={
          <label className="relative">
            <Search
              className="absolute left-2 top-1/2 -translate-y-1/2 text-text-secondary"
              width={14}
              height={14}
              aria-hidden="true"
            />
            <input
              className="ep-input pl-7"
              placeholder="Search interfaces"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              aria-label="Search interfaces"
              data-testid="interface-search"
            />
          </label>
        }
      />
      {interfaces.isLoading && <LoadingSkeleton label="Loading interfaces" />}
      {interfaces.error && !interfaces.isLoading && (
        <ErrorState
          title="Could not load interfaces"
          detail={(interfaces.error as Error).message}
          onRetry={() => void interfaces.refetch()}
        />
      )}

      {!interfaces.isLoading && !interfaces.error && !filtered.length && (
        <EmptyState
          title="No interfaces reported"
          description="The backend returned an empty set. Verify the probe deployment and that the API /interfaces endpoint lists the capture points."
        />
      )}

      {filtered.length > 0 && (
        <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_380px]">
          <div className="ep-card overflow-hidden">
            <table className="ep-table" data-testid="interface-table">
              <thead>
                <tr>
                  <th>Interface</th>
                  <th>Protocol</th>
                  <th>Linux device</th>
                  <th>Live capture</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((item) => {
                  const row = (
                    <tr
                      key={item.interface}
                      onClick={() =>
                        navigate(`/interfaces/${encodeURIComponent(item.interface)}`)
                      }
                      data-selected={selected?.interface === item.interface}
                      className="cursor-pointer"
                    >
                      <td>
                        <div className="flex flex-col">
                          <span className="font-medium">{item.interface}</span>
                          <span className="text-text-secondary text-ep-xs truncate">
                            {item.capture_point}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className="ep-badge">{item.protocol}</span>
                      </td>
                      <td className="mono text-ep-xs">
                        {item.device ?? '—'}
                      </td>
                      <td>
                        <StatusIndicator
                          state={
                            item.live_capture_available
                              ? 'AUTHORIZED'
                              : 'GATED'
                          }
                          compact
                        />
                      </td>
                      <td>
                        <StatusIndicator state={item.status} />
                      </td>
                    </tr>
                  );
                  return row;
                })}
              </tbody>
            </table>
            <div className="px-3 py-2 border-t border-border text-ep-xs text-text-secondary">
              Discovered{' '}
              <span className="num text-text-primary">
                {count(interfaces.data?.length)}
              </span>{' '}
              interfaces · aggregate storage used{' '}
              <span className="num text-text-primary">
                {bytes(
                  interfaces.data
                    ?.map((item) => item.file_size)
                    .filter((v): v is number => v != null)
                    .reduce((acc, v) => acc + v, 0),
                )}
              </span>
            </div>
          </div>
          <InterfaceInspector
            iface={selected}
            probes={probes.data}
            metrics={metrics.data}
            captures={captures.data?.items}
          />
        </div>
      )}
    </>
  );
}
