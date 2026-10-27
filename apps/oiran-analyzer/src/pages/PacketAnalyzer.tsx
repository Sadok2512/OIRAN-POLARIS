import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from '@tanstack/react-table';
import { AlertTriangle, Filter } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from '@/ui/EmptyErrorLoading';
import {
  DEFAULT_PACKETS_PAGE_SIZE,
  usePacket,
  usePackets,
} from '@/data/queries';
import { bytes, count, isoToLocal } from '@/data/format';
import type { Packet } from '@shared/types';
import { EventInspector } from '@/components/EventInspector';
import type { CallFlowEvent } from '@shared/types';

function packetToEvent(packet: Packet): CallFlowEvent {
  // The /packets endpoint already returns the decoded IE tree; adapt it
  // into the shape EventInspector consumes so we reuse that component.
  return {
    event_id: packet.event_id || packet.packet_id,
    timestamp: packet.timestamp,
    timestamp_ns: packet.timestamp_ns,
    interface: packet.interface,
    protocol: packet.protocol,
    message_name: packet.message_name || packet.protocol,
    source_participant: packet.source,
    destination_participant: packet.destination,
    direction: packet.direction,
    decoded_ie_tree: packet.information_elements,
    decoding_status: packet.decode_status,
    semantic_status: 'NORMAL',
    association: 'UNMATCHED',
    procedure_group: '',
    packet_references: [
      {
        source_file: packet.source_file,
        packet_number: packet.packet_number,
        byte_offset: packet.byte_offset,
        interface_id: 0,
        captured_length: packet.captured_length,
        original_length: packet.original_length,
      },
    ],
    capture_id: packet.capture_id,
    decoder_name: packet.decoder_name,
    decoder_version: packet.decoder_version,
    raw_payload_reference: packet.raw_payload_reference,
    errors: [],
  };
}

export function PacketAnalyzerPage() {
  const [params] = useSearchParams();
  const captureId = params.get('capture_id') ?? undefined;
  const sessionId = params.get('session_id') ?? undefined;

  const [page, setPage] = useState(1);
  const [pageSize] = useState(DEFAULT_PACKETS_PAGE_SIZE);
  const [sorting, setSorting] = useState<SortingState>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const packets = usePackets({ page, pageSize, captureId, sessionId });
  const packetDetail = usePacket(selectedId);

  const columns: ColumnDef<Packet>[] = [
    {
      accessorKey: 'packet_number',
      header: '#',
      cell: ({ row }) => <span className="num">{row.original.packet_number}</span>,
    },
    {
      accessorKey: 'timestamp',
      header: 'Timestamp',
      cell: ({ row }) => isoToLocal(row.original.timestamp),
    },
    { accessorKey: 'interface', header: 'Interface' },
    { accessorKey: 'protocol', header: 'Protocol' },
    { accessorKey: 'source', header: 'Source', cell: ({ row }) => <span className="mono text-ep-xs">{row.original.source}</span> },
    { accessorKey: 'destination', header: 'Destination', cell: ({ row }) => <span className="mono text-ep-xs">{row.original.destination}</span> },
    { accessorKey: 'message_name', header: 'Message' },
    {
      accessorKey: 'captured_length',
      header: 'Length',
      cell: ({ row }) => <span className="num">{bytes(row.original.captured_length)}</span>,
    },
    { accessorKey: 'decode_status', header: 'Status' },
  ];

  const table = useReactTable({
    data: packets.data?.items ?? [],
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const total = packets.data?.total ?? null;
  const totalPages = packets.data?.totalPages ?? null;
  const atFirst = page <= 1;
  const atLast =
    totalPages != null
      ? page >= totalPages
      : (packets.data?.items.length ?? 0) < pageSize;

  const detailEvent = packetDetail.data
    ? packetToEvent(packetDetail.data)
    : null;

  return (
    <>
      <PageHeader
        eyebrow="Analysis"
        title="Packet Analyzer"
        description="Virtualized packet inventory from the backend. Each packet preserves its capture_id and source file reference. Decoded information elements shown unmodified."
        actions={
          <span className="text-ep-xs text-text-secondary flex items-center gap-1.5">
            <Filter width={13} height={13} aria-hidden="true" />
            Filters: current page
            {total != null && ` · ${count(total)} total`}
          </span>
        }
      />

      {captureId || sessionId ? (
        <div className="ep-card p-3 mb-3 text-ep-xs text-text-secondary flex flex-wrap items-center gap-2" data-testid="scope-notice">
          Scope:
          {captureId && (
            <span className="ep-badge mono">capture={captureId}</span>
          )}
          {sessionId && (
            <span className="ep-badge mono">session={sessionId}</span>
          )}
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(320px,420px)]">
        <section className="ep-card overflow-hidden">
          {packets.isLoading && !packets.data ? (
            <LoadingSkeleton label="Loading packets" />
          ) : packets.error ? (
            <ErrorState
              title="Could not load packets"
              detail={(packets.error as Error).message}
              onRetry={() => void packets.refetch()}
            />
          ) : (packets.data?.items.length ?? 0) === 0 ? (
            <EmptyState
              title="No packets"
              description="The backend returned no packet for the current scope."
            />
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="ep-table" data-testid="packet-table">
                  <thead>
                    {table.getHeaderGroups().map((hg) => (
                      <tr key={hg.id}>
                        {hg.headers.map((header) => (
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
                        onClick={() => setSelectedId(row.original.packet_id)}
                        data-selected={selectedId === row.original.packet_id}
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
              <div className="flex items-center justify-between gap-2 px-3 py-2 border-t border-border text-ep-xs text-text-secondary">
                <span>
                  Page <span className="num text-text-primary">{page}</span>
                  {totalPages != null
                    ? ` of ${totalPages}`
                    : ' · total unknown'}
                </span>
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    className="ep-button ep-button-sm"
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={atFirst || packets.isFetching}
                  >
                    Previous
                  </button>
                  <button
                    type="button"
                    className="ep-button ep-button-sm"
                    onClick={() => setPage((p) => p + 1)}
                    disabled={atLast || packets.isFetching}
                  >
                    Next
                  </button>
                </div>
              </div>
              {packets.data?.totalUnknown && (
                <div className="px-3 py-2 flex items-start gap-2 text-ep-xs text-text-secondary border-t border-border">
                  <AlertTriangle
                    width={13}
                    height={13}
                    className="text-warning mt-0.5 shrink-0"
                  />
                  <span>
                    Backend did not report <code className="mono">meta.total</code>.
                    Showing current page only.
                  </span>
                </div>
              )}
            </>
          )}
        </section>
        <EventInspector event={detailEvent} onClose={() => setSelectedId(null)} />
      </div>
    </>
  );
}
