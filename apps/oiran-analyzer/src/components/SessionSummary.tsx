import { Clock, Radio, Share2, FileSearch } from 'lucide-react';
import type { Session } from '@shared/types';
import type { HierarchyPduSession } from '@/analyzer/hierarchy';
import { EvidenceBadge } from '@/ui/EvidenceBadge';
import { count, isoToLocal } from '@/data/format';

function fieldOrDash(value: string | undefined | null): string {
  if (value == null || value === '') return '—';
  return value;
}

export function SessionSummary({
  session,
  pdu,
}: {
  session: Session;
  pdu?: HierarchyPduSession;
}) {
  return (
    <section className="ep-card p-5" data-testid="session-summary">
      <header className="flex items-start justify-between gap-3 mb-4">
        <div>
          <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
            PDU Session Inspector
          </p>
          <h2 className="text-ep-h2 font-semibold mt-1">
            PDU {session.pdu_session_id} ·{' '}
            <span className="text-text-secondary font-normal">{session.procedure}</span>
          </h2>
          <p className="text-ep-xs text-text-secondary mt-0.5 mono break-all">
            {session.session_id}
          </p>
        </div>
        <EvidenceBadge confidence={session.correlation_status} />
      </header>

      <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-1 text-ep-sm">
        <dt className="text-text-secondary">UE pseudonym</dt>
        <dd>{fieldOrDash(session.ue_pseudonym)}</dd>
        <dt className="text-text-secondary">UE context</dt>
        <dd className="mono text-ep-xs break-all">{fieldOrDash(session.ue_context_id)}</dd>

        <dt className="text-text-secondary">Technology</dt>
        <dd>{fieldOrDash(session.technology)}</dd>
        <dt className="text-text-secondary">Serving node</dt>
        <dd>{fieldOrDash(session.serving_node)}</dd>

        <dt className="text-text-secondary">State</dt>
        <dd>{fieldOrDash(session.state)}</dd>
        <dt className="text-text-secondary">Dataset</dt>
        <dd className="mono text-ep-xs break-all">{fieldOrDash(session.dataset_id)}</dd>

        <dt className="text-text-secondary flex items-center gap-1">
          <Clock width={11} height={11} />
          Start
        </dt>
        <dd>{isoToLocal(session.start_timestamp)}</dd>
        <dt className="text-text-secondary flex items-center gap-1">
          <Clock width={11} height={11} />
          End
        </dt>
        <dd>{isoToLocal(session.end_timestamp)}</dd>

        <dt className="text-text-secondary flex items-center gap-1">
          <Radio width={11} height={11} />
          Interfaces
        </dt>
        <dd>{session.interfaces.join(' + ') || '—'}</dd>
        <dt className="text-text-secondary">Message count</dt>
        <dd className="num">{count(session.message_count)}</dd>

        <dt className="text-text-secondary">Decoded</dt>
        <dd className="num">{count(session.decode_completeness.decoded)}</dd>
        <dt className="text-text-secondary">Partial / Unresolved</dt>
        <dd className="num">
          {count(session.decode_completeness.partial)} /{' '}
          {count(session.decode_completeness.unresolved_fields)}
        </dd>
      </dl>

      {pdu && (
        <section className="mt-5 grid gap-3 md:grid-cols-3">
          <div>
            <h3 className="text-ep-sm font-semibold mb-1 flex items-center gap-1.5">
              <Share2 width={13} height={13} /> PFCP SEIDs
            </h3>
            {pdu.pfcpSeids.length ? (
              <ul className="flex flex-wrap gap-1">
                {pdu.pfcpSeids.map((seid) => (
                  <li key={seid}>
                    <span className="ep-badge mono">{seid}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-ep-xs text-text-secondary">
                No PFCP SEID exposed by the backend decoded tree.
              </p>
            )}
          </div>
          <div>
            <h3 className="text-ep-sm font-semibold mb-1 flex items-center gap-1.5">
              <Radio width={13} height={13} /> GTP-U TEIDs
            </h3>
            {pdu.gtpuTeids.length ? (
              <ul className="flex flex-wrap gap-1">
                {pdu.gtpuTeids.map((teid) => (
                  <li key={teid}>
                    <span className="ep-badge mono">{teid}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-ep-xs text-text-secondary">
                No GTP-U TEID exposed by the backend decoded tree.
              </p>
            )}
          </div>
          <div>
            <h3 className="text-ep-sm font-semibold mb-1 flex items-center gap-1.5">
              <FileSearch width={13} height={13} /> Encapsulated flows
            </h3>
            {pdu.flows.length ? (
              <ul className="flex flex-col gap-1 text-ep-xs">
                {pdu.flows.slice(0, 6).map((flow, index) => (
                  <li key={`${flow.source}-${flow.destination}-${index}`}>
                    <span className="ep-badge mono mr-1">{flow.protocol}</span>
                    <span className="mono">
                      {flow.source} → {flow.destination}
                    </span>
                    <span className="text-text-secondary ml-1">
                      · {count(flow.packetCount)} pkt
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-ep-xs text-text-secondary">
                No N3 / GTP-U flow events reported for this session.
              </p>
            )}
          </div>
        </section>
      )}
    </section>
  );
}
