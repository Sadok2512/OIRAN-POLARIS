import { useCallback, useMemo, useState } from 'react';
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from '@tanstack/react-table';
import { AlertTriangle, Download, Eye, FileSearch, Filter, Loader2 } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from '@/ui/EmptyErrorLoading';
import {
  DEFAULT_CAPTURE_PAGE_SIZE,
  useAuth,
  useCapturesPage,
  useInterfaces,
  useProbes,
} from '@/data/queries';
import { bytes, count, durationSeconds, isoToLocal } from '@/data/format';
import type { Capture } from '@shared/types';
import { ApiError, authenticatedDownload } from '@shared/api';

const STATUS_OPTIONS: Capture['state'][] = [
  'READY',
  'STARTING',
  'CAPTURING',
  'STOPPING',
  'COMPLETED',
  'COMPLETED_EMPTY',
  'FAILED',
];

type CaptureLibraryPageProps = {
  /** Default page size override, used by tests. */
  defaultPageSize?: number;
};

export function CaptureLibraryPage({
  defaultPageSize = DEFAULT_CAPTURE_PAGE_SIZE,
}: CaptureLibraryPageProps = {}) {
  const [page, setPage] = useState(1);
  const [pageSize] = useState(defaultPageSize);
  const captures = useCapturesPage({ page, pageSize });
  const probes = useProbes();
  const interfaces = useInterfaces();
  const auth = useAuth();

  const [selected, setSelected] = useState<Capture | null>(null);
  const [search, setSearch] = useState('');
  const [probeFilter, setProbeFilter] = useState('');
  const [interfaceFilter, setInterfaceFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sorting, setSorting] = useState<SortingState>([]);

  // Filters apply to the current page returned by the backend. If the
  // backend exposes server-side filters later, these can forward through
  // the query string instead. For now we're explicit about the scope.
  const pageItems = captures.data?.items ?? [];
  const filtered = useMemo(
    () =>
      pageItems.filter((capture) => {
        if (
          search &&
          !`${capture.name} ${capture.capture_id} ${capture.interface ?? ''} ${capture.interfaces?.join(' ') ?? ''}`
            .toLowerCase()
            .includes(search.toLowerCase())
        )
          return false;
        if (probeFilter && capture.probe_id !== probeFilter) return false;
        if (
          interfaceFilter &&
          !(
            capture.interface === interfaceFilter ||
            capture.interfaces?.includes(interfaceFilter)
          )
        )
          return false;
        if (statusFilter && capture.state !== statusFilter) return false;
        return true;
      }),
    [pageItems, search, probeFilter, interfaceFilter, statusFilter],
  );

  const authenticated = auth.data?.authenticated === true;

  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const triggerDownload = useCallback(async (capture: Capture) => {
    setDownloadError(null);
    setDownloadingId(capture.capture_id);
    try {
      const dl = await authenticatedDownload(
        `/captures/${encodeURIComponent(capture.capture_id)}/download`,
        { authScope: 'oiran' },
      );
      try {
        const anchor = document.createElement('a');
        anchor.href = dl.objectUrl;
        anchor.download = dl.filename ?? `${capture.name}.pcap`;
        anchor.rel = 'noopener';
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
      } finally {
        dl.revoke();
      }
    } catch (error) {
      setDownloadError(
        error instanceof ApiError
          ? `Download failed: HTTP ${error.status} ${error.code}`
          : error instanceof Error
            ? error.message
            : 'Download failed',
      );
    } finally {
      setDownloadingId(null);
    }
  }, []);

  const columns = useMemo<ColumnDef<Capture>[]>(
    () => [
      {
        accessorKey: 'name',
        header: 'Capture name',
        cell: ({ row }) => (
          <div className="flex items-center gap-2">
            <FileSearch width={14} height={14} className="text-text-secondary shrink-0" />
            <div className="min-w-0">
              <div className="font-medium truncate">{row.original.name}</div>
              <div className="mono text-ep-xs text-text-secondary truncate">
                {row.original.capture_id.slice(0, 32)}…
              </div>
            </div>
          </div>
        ),
      },
      {
        accessorKey: 'probe_id',
        header: 'Probe',
        cell: ({ row }) => row.original.probe_id ?? '—',
      },
      {
        id: 'interfaces',
        header: 'Interfaces',
        cell: ({ row }) =>
          row.original.interface ??
          row.original.interfaces?.join(' + ') ??
          '—',
      },
      {
        accessorKey: 'protocol',
        header: 'Protocol',
        cell: ({ row }) => row.original.protocol ?? '—',
      },
      {
        id: 'start',
        header: 'Start time',
        accessorFn: (capture) => capture.planes?.[0]?.start_timestamp ?? 0,
        cell: ({ row }) => {
          const start = row.original.planes?.[0]?.start_timestamp;
          return start
            ? isoToLocal(new Date(start * 1000).toISOString())
            : '—';
        },
      },
      {
        id: 'duration',
        header: 'Duration',
        cell: ({ row }) =>
          row.original.planes?.[0]
            ? durationSeconds(
                row.original.planes[0].start_timestamp,
                row.original.planes[0].end_timestamp,
              )
            : '—',
      },
      {
        id: 'packet_count',
        header: 'Packets',
        accessorFn: (capture) =>
          capture.packet_count ?? capture.metrics?.packets_received ?? 0,
        cell: ({ row }) => (
          <span className="num">
            {count(
              row.original.packet_count ??
                row.original.metrics?.packets_received,
            )}
          </span>
        ),
      },
      {
        id: 'size',
        header: 'Size',
        accessorFn: (capture) =>
          capture.size_bytes ?? capture.metrics?.storage_bytes ?? 0,
        cell: ({ row }) => (
          <span className="num">
            {bytes(
              row.original.size_bytes ?? row.original.metrics?.storage_bytes,
            )}
          </span>
        ),
      },
      {
        accessorKey: 'state',
        header: 'Status',
        cell: ({ row }) => (
          <StatusIndicator state={row.original.state ?? 'UNKNOWN'} />
        ),
      },
      {
        id: 'dataset',
        header: 'Dataset',
        cell: ({ row }) =>
          row.original.dataset_id ? (
            <span className="mono text-ep-xs">
              {row.original.dataset_id.slice(0, 10)}…
            </span>
          ) : (
            <span className="text-ep-xs text-text-secondary">
              Not registered
            </span>
          ),
      },
      {
        id: 'actions',
        header: 'Actions',
        cell: ({ row }) => {
          const capture = row.original;
          const failed = (capture.state ?? capture.status) === 'FAILED';
          const sizeBytes =
            capture.size_bytes ?? capture.metrics?.storage_bytes ?? null;
          const downloadable = authenticated && (sizeBytes ?? 0) > 0;
          const analyzerUrl = capture.dataset_id
            ? `/oiran/#/investigation/sessions?capture_id=${encodeURIComponent(capture.capture_id)}&dataset_id=${encodeURIComponent(capture.dataset_id)}`
            : null;
          return (
            <div className="flex items-center gap-1">
              <button
                type="button"
                className="ep-button ep-button-sm"
                aria-label={`View capture ${capture.name}`}
                onClick={(event) => {
                  event.stopPropagation();
                  setSelected(capture);
                }}
                data-testid={`view-${capture.capture_id}`}
              >
                <Eye width={13} height={13} aria-hidden="true" />
                View
              </button>
              {analyzerUrl ? (
                <a
                  className="ep-button ep-button-sm"
                  href={analyzerUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(event) => event.stopPropagation()}
                  data-testid={`analyzer-${capture.capture_id}`}
                >
                  Analyzer
                </a>
              ) : (
                <button
                  type="button"
                  className="ep-button ep-button-sm"
                  disabled
                  title="Dataset not registered — cannot open in Analyzer"
                  data-testid={`analyzer-${capture.capture_id}`}
                >
                  Analyzer
                </button>
              )}
              <button
                type="button"
                className="ep-button ep-button-sm"
                disabled={!downloadable || downloadingId === capture.capture_id}
                aria-label={
                  downloadable
                    ? `Download PCAP for ${capture.name}`
                    : 'Download disabled'
                }
                title={
                  !authenticated
                    ? 'Download requires an authenticated operator role'
                    : !downloadable
                      ? 'Capture has no stored bytes — nothing to download'
                      : 'Download PCAP (Bearer-authenticated, token not in URL)'
                }
                data-testid={`download-${capture.capture_id}`}
                onClick={(event) => {
                  event.stopPropagation();
                  void triggerDownload(capture);
                }}
              >
                {downloadingId === capture.capture_id ? (
                  <Loader2 width={13} height={13} className="animate-spin" aria-hidden="true" />
                ) : (
                  <Download width={13} height={13} aria-hidden="true" />
                )}
              </button>
              {failed && (
                <span
                  className="ep-badge border-error/40 text-error"
                  title={capture.error ?? 'Capture failed'}
                >
                  View error
                </span>
              )}
            </div>
          );
        },
      },
    ],
    [authenticated],
  );

  const table = useReactTable({
    data: filtered,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    // No TanStack-paginated model: pagination is server-side.
  });

  const total = captures.data?.total ?? null;
  const totalPages = captures.data?.totalPages ?? null;
  const totalUnknown = captures.data?.totalUnknown ?? true;
  const atFirst = page <= 1;
  const atLast = totalPages != null ? page >= totalPages : pageItems.length < pageSize;

  return (
    <>
      <PageHeader
        eyebrow="Capture"
        title="Capture Library"
        description="Every capture record reported by the backend. Original PCAPs stay immutable; opening in Analyzer preserves the capture and dataset context."
        actions={
          <div className="flex items-center gap-2">
            <span
              className="ep-badge"
              title="Filters and sorting apply to the CURRENT page only. Pagination is server-driven."
              data-testid="filter-scope-badge"
            >
              <Filter width={11} height={11} aria-hidden="true" />
              Filters: current page
            </span>
            <span className="text-ep-xs text-text-secondary">
              {count(filtered.length)} shown
              {total != null && ` of ${count(total)} total`}
            </span>
          </div>
        }
      />

      {downloadError && (
        <div
          role="alert"
          className="ep-card border-error/30 p-3 mb-3 text-ep-sm text-error"
          data-testid="download-error"
        >
          {downloadError}
        </div>
      )}

      <div
        className="ep-card p-3 flex flex-wrap items-center gap-2 mb-4"
        data-testid="capture-filters"
      >
        <p
          className="w-full text-ep-xs text-text-secondary"
          data-testid="filter-scope-note"
        >
          Search · sort · filters below act on the <strong>current page only</strong>;
          use Previous/Next to request additional pages from the backend.
        </p>
        <input
          className="ep-input flex-1 min-w-[200px]"
          placeholder="Search by name, ID, interface (current page)"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          aria-label="Search captures (current page)"
          data-testid="capture-search"
        />
        <select
          className="ep-input"
          value={probeFilter}
          onChange={(event) => setProbeFilter(event.target.value)}
          aria-label="Filter by probe"
        >
          <option value="">All probes</option>
          {probes.data?.map((probe) => (
            <option key={probe.probe_id} value={probe.probe_id}>
              {probe.name}
            </option>
          ))}
        </select>
        <select
          className="ep-input"
          value={interfaceFilter}
          onChange={(event) => setInterfaceFilter(event.target.value)}
          aria-label="Filter by interface"
        >
          <option value="">All interfaces</option>
          {interfaces.data?.map((item) => (
            <option key={item.interface} value={item.interface}>
              {item.interface}
            </option>
          ))}
        </select>
        <select
          className="ep-input"
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value)}
          aria-label="Filter by status"
        >
          <option value="">All statuses</option>
          {STATUS_OPTIONS.map((state) => (
            <option key={state} value={state ?? ''}>
              {state}
            </option>
          ))}
        </select>
      </div>

      {captures.isLoading && !captures.data && (
        <LoadingSkeleton label="Loading capture inventory" />
      )}

      {captures.error && !captures.isLoading && (
        <ErrorState
          title="Could not load captures"
          detail={(captures.error as Error).message}
          onRetry={() => void captures.refetch()}
        />
      )}

      {!captures.isLoading && !captures.error && !filtered.length && (
        <EmptyState
          title={
            totalUnknown
              ? 'No captures on this page'
              : total === 0
                ? 'No captures match'
                : 'No captures match the current filters'
          }
          description={
            totalUnknown
              ? 'The backend did not advertise a total; try the previous page.'
              : 'Adjust the filters or wait for the backend to register captures.'
          }
        />
      )}

      {filtered.length > 0 && (
        <div className="ep-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="ep-table" data-testid="capture-table">
              <thead>
                {table.getHeaderGroups().map((headerGroup) => (
                  <tr key={headerGroup.id}>
                    {headerGroup.headers.map((header) => (
                      <th
                        key={header.id}
                        onClick={header.column.getToggleSortingHandler()}
                        className={
                          header.column.getCanSort() ? 'cursor-pointer' : ''
                        }
                      >
                        {flexRender(
                          header.column.columnDef.header,
                          header.getContext(),
                        )}
                        {header.column.getIsSorted() === 'asc'
                          ? ' ▲'
                          : header.column.getIsSorted() === 'desc'
                            ? ' ▼'
                            : ''}
                      </th>
                    ))}
                  </tr>
                ))}
              </thead>
              <tbody>
                {table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    data-selected={selected?.capture_id === row.original.capture_id}
                    onClick={() => setSelected(row.original)}
                    className="cursor-pointer"
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id}>
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext(),
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div
            className="flex items-center justify-between gap-2 px-3 py-2 border-t border-border text-ep-xs text-text-secondary"
            data-testid="capture-pagination"
          >
            <span>
              Page <span className="num text-text-primary">{page}</span>
              {totalPages != null ? (
                <>
                  {' '}of <span className="num text-text-primary">{totalPages}</span>
                </>
              ) : (
                ' · total unknown'
              )}
              {' · '}
              Showing <span className="num text-text-primary">{pageItems.length}</span>
              {' / '}
              <span className="num text-text-primary">{pageSize}</span>
            </span>
            <div className="flex items-center gap-1">
              <button
                type="button"
                className="ep-button ep-button-sm"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={atFirst || captures.isFetching}
                data-testid="pagination-previous"
              >
                Previous
              </button>
              <button
                type="button"
                className="ep-button ep-button-sm"
                onClick={() => setPage((p) => p + 1)}
                disabled={atLast || captures.isFetching}
                data-testid="pagination-next"
              >
                Next
              </button>
            </div>
          </div>
          {totalUnknown && pageItems.length === pageSize && (
            <div
              className="px-3 py-2 flex items-start gap-2 text-ep-xs text-text-secondary border-t border-border"
              data-testid="partial-results-notice"
            >
              <AlertTriangle
                width={13}
                height={13}
                className="text-warning mt-0.5 shrink-0"
                aria-hidden="true"
              />
              <span>
                The backend did not report <code className="mono">meta.total</code>.
                Showing only the current page; later pages may exist. See
                <code className="mono"> docs/frontend/API_INTEGRATION_GAPS.md</code>.
              </span>
            </div>
          )}
        </div>
      )}

      {selected && (
        <aside
          className="ep-card mt-4 p-4"
          data-testid="capture-detail"
          aria-label="Selected capture metadata"
        >
          <header className="flex items-start justify-between gap-3">
            <div>
              <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
                Capture metadata
              </p>
              <h2 className="text-ep-lg font-semibold">{selected.name}</h2>
              <p className="mono text-ep-xs text-text-secondary break-all">
                {selected.capture_id}
              </p>
            </div>
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={() => setSelected(null)}
              aria-label="Close capture metadata"
            >
              Close
            </button>
          </header>
          <dl className="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-1 text-ep-sm mt-3">
            <dt className="text-text-secondary">Probe</dt>
            <dd>{selected.probe_id ?? '—'}</dd>
            <dt className="text-text-secondary">Interfaces</dt>
            <dd>{selected.interface ?? selected.interfaces?.join(' + ') ?? '—'}</dd>
            <dt className="text-text-secondary">Protocol</dt>
            <dd>{selected.protocol ?? '—'}</dd>
            <dt className="text-text-secondary">Dataset</dt>
            <dd className="mono break-all">{selected.dataset_id ?? 'Not registered'}</dd>
            <dt className="text-text-secondary">Packets</dt>
            <dd className="num">{count(selected.packet_count ?? selected.metrics?.packets_received)}</dd>
            <dt className="text-text-secondary">Size</dt>
            <dd className="num">{bytes(selected.size_bytes ?? selected.metrics?.storage_bytes)}</dd>
            {selected.error && (
              <>
                <dt className="text-text-secondary">Error</dt>
                <dd className="col-span-2 break-words">{selected.error}</dd>
              </>
            )}
          </dl>
        </aside>
      )}
    </>
  );
}
