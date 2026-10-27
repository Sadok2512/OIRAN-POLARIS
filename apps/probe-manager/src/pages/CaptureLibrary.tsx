import { useMemo, useState } from 'react';
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from '@tanstack/react-table';
import { Download, FileSearch, Filter } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from '@/ui/EmptyErrorLoading';
import {
  useCaptures,
  useInterfaces,
  useProbes,
} from '@/data/queries';
import { bytes, count, durationSeconds, isoToLocal } from '@/data/format';
import type { Capture } from '@shared/types';

const STATUS_OPTIONS: Capture['state'][] = [
  'READY',
  'STARTING',
  'CAPTURING',
  'STOPPING',
  'COMPLETED',
  'COMPLETED_EMPTY',
  'FAILED',
];

export function CaptureLibraryPage() {
  const captures = useCaptures();
  const probes = useProbes();
  const interfaces = useInterfaces();

  const [search, setSearch] = useState('');
  const [probeFilter, setProbeFilter] = useState('');
  const [interfaceFilter, setInterfaceFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sorting, setSorting] = useState<SortingState>([]);

  const data = useMemo(
    () =>
      captures.data?.filter((capture) => {
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
      }) ?? [],
    [captures.data, search, probeFilter, interfaceFilter, statusFilter],
  );

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
          return (
            <div className="flex items-center gap-1">
              <button
                type="button"
                className="ep-button ep-button-sm"
                aria-label="View capture"
                onClick={(event) => event.stopPropagation()}
                data-testid={`view-${capture.capture_id}`}
              >
                View
              </button>
              {capture.dataset_id ? (
                <a
                  className="ep-button ep-button-sm"
                  href={`/oiran/#/investigation/sessions?capture_id=${encodeURIComponent(capture.capture_id)}&dataset_id=${encodeURIComponent(capture.dataset_id)}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(event) => event.stopPropagation()}
                >
                  Analyzer
                </a>
              ) : (
                <button
                  type="button"
                  className="ep-button ep-button-sm"
                  disabled
                  title="Dataset not registered — cannot open in Analyzer"
                >
                  Analyzer
                </button>
              )}
              <a
                className="ep-button ep-button-sm"
                href={`/api/v1/captures/${encodeURIComponent(capture.capture_id)}`}
                onClick={(event) => event.stopPropagation()}
                aria-label="Download PCAP metadata"
              >
                <Download width={13} height={13} aria-hidden="true" />
              </a>
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
    [],
  );

  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 20 } },
  });

  return (
    <>
      <PageHeader
        eyebrow="Capture"
        title="Capture Library"
        description="Every capture record reported by the backend. Original PCAPs stay immutable; opening in Analyzer preserves the capture and dataset context."
        actions={
          <span className="text-ep-xs text-text-secondary flex items-center gap-1.5">
            <Filter width={13} height={13} aria-hidden="true" />
            {count(data.length)} of {count(captures.data?.length)} records
          </span>
        }
      />

      <div className="ep-card p-3 flex flex-wrap items-center gap-2 mb-4">
        <input
          className="ep-input flex-1 min-w-[200px]"
          placeholder="Search by name, ID, interface"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          aria-label="Search captures"
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

      {captures.isLoading && <LoadingSkeleton label="Loading capture inventory" />}

      {captures.error && !captures.isLoading && (
        <ErrorState
          title="Could not load captures"
          detail={(captures.error as Error).message}
          onRetry={() => void captures.refetch()}
        />
      )}

      {!captures.isLoading && !captures.error && !data.length && (
        <EmptyState
          title="No captures match"
          description="Adjust the filters or wait for the backend to register captures."
        />
      )}

      {data.length > 0 && (
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
                  <tr key={row.id}>
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
          <div className="flex items-center justify-between gap-2 px-3 py-2 border-t border-border text-ep-xs text-text-secondary">
            <span>
              Page {table.getState().pagination.pageIndex + 1} of{' '}
              {Math.max(1, table.getPageCount())}
            </span>
            <div className="flex items-center gap-1">
              <button
                type="button"
                className="ep-button ep-button-sm"
                onClick={() => table.previousPage()}
                disabled={!table.getCanPreviousPage()}
              >
                Previous
              </button>
              <button
                type="button"
                className="ep-button ep-button-sm"
                onClick={() => table.nextPage()}
                disabled={!table.getCanNextPage()}
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
