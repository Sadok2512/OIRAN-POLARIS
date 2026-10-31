// 2.4.0 — Overview rebuilt to match docs/ui-mockups/oiran-analyzer.html.
// Four stat tiles (Datasets / Sessions / Events / Decode errors), a
// "Latest sessions" card linking to the Sessions page, and a
// "Decoder versions" card fed from /modules. Values are live from the
// OIRAN 2.5.x API (/datasets, /sessions, /metrics, /modules). The page
// never surfaces subscriber identities — UE columns stay on the pseudonym.

import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../services/api';
import type { Dataset, Metrics, Module, Session } from '../types/api';
import { ErrorState, LoadingState } from '../components/AsyncState';
import {
  Card,
  IfChip,
  PageHeader,
  Pill,
  Stat,
  confTone,
} from '../components/mockup';

const DECODER_PINS = [
  ['NGAP', 'ngap'],
  ['NAS-5GS', 'nas'],
  ['PFCP', 'pfcp'],
  ['SBI', 'sbi'],
  ['GTP-U', 'gtpu'],
  ['Session engine', 'session'],
] as const;

function pickDecoderVersion(modules: Module[] | undefined, key: string): string {
  if (!modules) return '—';
  const needle = key.toLowerCase();
  const match = modules.find((m) => m.module_id.toLowerCase().includes(needle));
  return match?.module_version ?? '—';
}

export function Overview() {
  const datasets = useQuery({
    queryKey: ['datasets-overview'],
    queryFn: () => api<Dataset[]>('/datasets?page_size=100').then((x) => x.data),
  });
  const sessions = useQuery({
    queryKey: ['sessions-overview'],
    queryFn: () => api<Session[]>('/sessions?page_size=100').then((x) => x.data),
  });
  const metrics = useQuery({
    queryKey: ['metrics'],
    queryFn: () => api<Metrics>('/metrics').then((x) => x.data),
    refetchInterval: 5000,
  });
  const modules = useQuery({
    queryKey: ['modules-overview'],
    queryFn: () => api<Module[]>('/modules').then((x) => x.data),
  });

  const kinds = useMemo(() => {
    const data = datasets.data ?? [];
    const live = data.filter((d) => d.dataset_kind === 'CAPTURED_LIVE').length;
    const historical = data.filter((d) => d.dataset_kind === 'HISTORICAL').length;
    const recovered = data.filter((d) => d.dataset_kind === 'RECOVERED').length;
    return { total: data.length, live, historical, recovered };
  }, [datasets.data]);

  const latest = useMemo(() => (sessions.data ?? []).slice(0, 4), [sessions.data]);

  const totalEvents = useMemo(
    () => (datasets.data ?? []).reduce((acc, d) => acc + (d.event_count ?? 0), 0),
    [datasets.data],
  );

  const loading =
    datasets.isLoading && sessions.isLoading && metrics.isLoading && modules.isLoading;
  const error = datasets.error || sessions.error || metrics.error;

  if (loading) return <LoadingState />;
  if (error)
    return (
      <ErrorState
        error={error as Error}
        retry={() => {
          void datasets.refetch();
          void sessions.refetch();
          void metrics.refetch();
          void modules.refetch();
        }}
      />
    );

  return (
    <>
      <PageHeader
        eyebrow="Investigate"
        title="Overview"
        desc="Datasets, reconstructed sessions and decode quality across everything the probes have captured."
      />
      <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
        <Stat
          label="Datasets"
          value={kinds.total.toString()}
          sub={`${kinds.live} live · ${kinds.historical} historical · ${kinds.recovered} recovered`}
        />
        <Stat
          label="Sessions"
          value={(sessions.data?.length ?? 0).toString()}
          sub="reconstructed PDU sessions"
        />
        <Stat
          label="Events"
          value={totalEvents.toLocaleString('en-US')}
          sub={`${metrics.data?.decode_errors ?? 0} decode errors`}
        />
        <Stat
          label="Decode errors"
          value={(metrics.data?.decode_errors ?? 0).toString()}
          sub="malformed messages"
        />
      </div>
      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_360px] items-start">
        <Card className="overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-line">
            <h2 className="font-semibold">Latest sessions</h2>
            <Link
              to="/investigation/sessions"
              className="text-sm2 text-brand inline-flex items-center gap-1"
              data-testid="overview-all-sessions"
            >
              All sessions <ChevronRight width={13} height={13} />
            </Link>
          </div>
          {latest.length === 0 ? (
            <p className="px-4 py-6 text-sm2 text-mute">No session yet.</p>
          ) : (
            <ul className="divide-y divide-line">
              {latest.map((s) => (
                <li key={s.session_id}>
                  <Link
                    to={`/investigation/callflow/${encodeURIComponent(s.session_id)}`}
                    className="w-full text-left px-4 py-3 flex flex-wrap items-center gap-x-4 gap-y-1 hover:bg-canvas"
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block font-medium truncate">{s.procedure}</span>
                      <span
                        className="block mono text-xs2 text-mute truncate"
                        title={s.session_id}
                      >
                        {s.session_id}
                      </span>
                    </span>
                    <span className="flex gap-1">
                      {s.interfaces.map((i) => (
                        <IfChip key={i} i={i} />
                      ))}
                    </span>
                    <span className="mono text-sm2 text-mute w-24 text-right">
                      {s.start_timestamp.slice(11, 19)}
                    </span>
                    <Pill tone={confTone(s.correlation_status)}>{s.correlation_status}</Pill>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card className="p-5">
          <h2 className="font-semibold mb-3">Decoder versions</h2>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2.5">
            {DECODER_PINS.map(([label, key]) => (
              <div key={key} className="min-w-0">
                <dt className="text-xs2 uppercase tracking-wider text-mute">{label}</dt>
                <dd className="mono text-sm2 truncate">
                  {pickDecoderVersion(modules.data, key)}
                </dd>
              </div>
            ))}
          </dl>
          <p className="mt-4 border-t border-line pt-3 text-sm2 text-mute">
            All datasets are read-only. Analysis never changes a capture.
          </p>
        </Card>
      </div>
    </>
  );
}
