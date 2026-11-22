import { useMemo, useState } from 'react';
import clsx from 'clsx';
import type { CallFlow, CallFlowEvent } from '@shared/types';

const DEFAULT_PARTICIPANTS = ['UE', 'gNB', 'AMF', 'SMF', 'UPF'];

const PROTOCOLS = ['NGAP', 'NAS', 'SBI', 'PFCP', 'GTP-U'] as const;
type ProtocolFilter = (typeof PROTOCOLS)[number] | 'ALL';

function normalizeParticipantId(raw: string): string {
  if (!raw) return 'UE';
  const upper = raw.toUpperCase();
  if (upper.includes('UE')) return 'UE';
  if (upper.includes('GNB') || upper.includes('ENB') || upper.includes('RAN')) return 'gNB';
  if (upper.includes('AMF')) return 'AMF';
  if (upper.includes('SMF')) return 'SMF';
  if (upper.includes('UPF')) return 'UPF';
  return raw;
}

function matchesProtocol(event: CallFlowEvent, filter: ProtocolFilter): boolean {
  if (filter === 'ALL') return true;
  const haystack = `${event.protocol} ${event.message_name}`.toUpperCase();
  if (filter === 'NAS') return haystack.includes('NAS');
  if (filter === 'NGAP') return haystack.includes('NGAP');
  if (filter === 'SBI') return haystack.includes('SBI') || haystack.includes('HTTP');
  if (filter === 'PFCP') return haystack.includes('PFCP');
  if (filter === 'GTP-U') return haystack.includes('GTP');
  return true;
}

export function CallFlowLadder({
  callflow,
  onSelect,
  highlightEventId,
}: {
  callflow: CallFlow;
  onSelect: (event: CallFlowEvent) => void;
  highlightEventId?: string;
}) {
  const participants = useMemo(() => {
    const seen = new Set<string>();
    for (const event of callflow.events) {
      seen.add(normalizeParticipantId(event.source_participant));
      seen.add(normalizeParticipantId(event.destination_participant));
    }
    const ordered = DEFAULT_PARTICIPANTS.filter((p) => seen.has(p));
    const extras = [...seen].filter((p) => !DEFAULT_PARTICIPANTS.includes(p));
    return [...ordered, ...extras.sort()];
  }, [callflow.events]);
  const [protocolFilter, setProtocolFilter] = useState<ProtocolFilter>('ALL');

  const filteredEvents = useMemo(
    () =>
      callflow.events
        .filter((event) => matchesProtocol(event, protocolFilter))
        .sort(
          (a, b) =>
            BigInt(a.timestamp_ns || 0) < BigInt(b.timestamp_ns || 0) ? -1 : 1,
        ),
    [callflow.events, protocolFilter],
  );

  if (!participants.length) {
    return (
      <p className="text-ep-xs text-text-secondary">
        Backend did not return any participant for this session.
      </p>
    );
  }

  const columnWidth = 220;
  const rowHeight = 44;

  return (
    <div className="ep-card p-4" data-testid="callflow-ladder">
      <div className="flex items-center justify-between mb-3 gap-3">
        <h3 className="text-ep-md font-semibold">
          Signaling Call Flow
          <span className="text-ep-xs text-text-secondary font-normal ml-2">
            {filteredEvents.length} / {callflow.events.length} messages
          </span>
        </h3>
        <div className="flex items-center gap-1 text-ep-xs">
          <span className="text-text-secondary mr-1">Filter:</span>
          {(['ALL', ...PROTOCOLS] as const).map((proto) => (
            <button
              key={proto}
              type="button"
              className={clsx(
                'ep-badge cursor-pointer',
                protocolFilter === proto &&
                  'bg-primary/10 text-primary border-primary/30',
              )}
              onClick={() => setProtocolFilter(proto)}
              data-testid={`callflow-filter-${proto}`}
            >
              {proto}
            </button>
          ))}
        </div>
      </div>

      <div
        className="relative overflow-x-auto"
        style={{ minWidth: participants.length * columnWidth }}
      >
        {/* Participant headers */}
        <div
          className="grid border-b border-border pb-2 mb-2 font-semibold text-ep-xs uppercase tracking-wider text-text-secondary"
          style={{
            gridTemplateColumns: `repeat(${participants.length}, minmax(${columnWidth}px, 1fr))`,
          }}
        >
          {participants.map((p) => (
            <div key={p} className="text-center">
              {p}
            </div>
          ))}
        </div>

        {/* Vertical lifelines */}
        <div
          className="relative"
          style={{ height: filteredEvents.length * rowHeight + 24 }}
        >
          {participants.map((_, index) => (
            <div
              key={index}
              className="absolute top-0 bottom-0 border-l border-border/60"
              style={{
                left: `calc(${(100 / participants.length) * index}% + ${columnWidth / 2 / participants.length}px)`,
              }}
              aria-hidden="true"
            />
          ))}

          {/* Message rows */}
          {filteredEvents.map((event, index) => {
            const srcCol = participants.indexOf(
              normalizeParticipantId(event.source_participant),
            );
            const dstCol = participants.indexOf(
              normalizeParticipantId(event.destination_participant),
            );
            if (srcCol < 0 || dstCol < 0) return null;
            const left = Math.min(srcCol, dstCol);
            const width = Math.max(1, Math.abs(dstCol - srcCol));
            const reverse = dstCol < srcCol;
            const highlighted = event.event_id === highlightEventId;
            return (
              <button
                key={event.event_id}
                type="button"
                onClick={() => onSelect(event)}
                data-testid={`callflow-event-${event.event_id}`}
                className={clsx(
                  'absolute flex items-center text-ep-xs rounded',
                  'hover:bg-canvas focus:bg-canvas text-left transition-colors',
                  highlighted ? 'bg-primary/5 ring-1 ring-primary' : '',
                )}
                style={{
                  top: index * rowHeight,
                  left: `calc(${(100 / participants.length) * left}% + 4px)`,
                  width: `calc(${(100 / participants.length) * width}% - 8px)`,
                  height: rowHeight - 6,
                }}
                title={`${event.message_name} · ${event.interface} · ${event.protocol}`}
              >
                <ArrowRow reverse={reverse}>
                  <span className="font-medium truncate">
                    {event.message_name}
                  </span>
                  <span className="text-text-secondary mono shrink-0 ml-2">
                    {event.interface} · {event.protocol}
                  </span>
                </ArrowRow>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function ArrowRow({
  reverse,
  children,
}: {
  reverse: boolean;
  children: React.ReactNode;
}) {
  return (
    <div
      className={clsx(
        'flex items-center w-full px-2 border border-border rounded bg-surface',
        'relative',
      )}
    >
      <span
        aria-hidden="true"
        className={clsx(
          'absolute top-1/2 -translate-y-1/2 h-0.5 bg-primary/70',
          reverse ? 'left-0 right-2' : 'left-2 right-0',
        )}
      />
      <span
        aria-hidden="true"
        className={clsx(
          'absolute top-1/2 -translate-y-1/2 h-2 w-2 bg-primary/70',
          reverse
            ? 'left-0 clip-arrow-left'
            : 'right-0 clip-arrow-right',
        )}
        style={{
          clipPath: reverse
            ? 'polygon(0 50%, 100% 0, 100% 100%)'
            : 'polygon(100% 50%, 0 0, 0 100%)',
        }}
      />
      <span className="relative z-10 flex items-center gap-1 w-full">
        {children}
      </span>
    </div>
  );
}
