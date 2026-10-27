import { useQuery } from '@tanstack/react-query';
import { api, type ApiOptions } from '@shared/api';
import type {
  ApiEnvelope,
  AuthState,
  CallFlow,
  CallFlowEvent,
  CorrelationEdge,
  Dataset,
  Metrics,
  Packet,
  Session,
  UeContext,
  VersionInfo,
} from '@shared/types';

// All Analyzer requests go through the OIRAN scope: the shared client
// will only attach the OIRAN bearer when it is stored under
// `oiran.access_token` AND the base is allowlisted (/api/v1).
const OIRAN_SCOPE: ApiOptions = { authScope: 'oiran' };

export function useVersion() {
  return useQuery({
    queryKey: ['version'],
    queryFn: () => api<VersionInfo>('/version', OIRAN_SCOPE).then((x) => x.data),
    staleTime: 60_000,
  });
}

export function useAuth() {
  return useQuery({
    queryKey: ['auth'],
    queryFn: () => api<AuthState>('/auth/me', OIRAN_SCOPE).then((x) => x.data),
    refetchInterval: 15_000,
    retry: false,
  });
}

export function useMetrics() {
  return useQuery({
    queryKey: ['metrics'],
    queryFn: () => api<Metrics>('/metrics', OIRAN_SCOPE).then((x) => x.data),
    refetchInterval: 5_000,
  });
}

export function useDatasets() {
  return useQuery({
    queryKey: ['datasets'],
    queryFn: () =>
      api<Dataset[]>('/datasets?page_size=200', OIRAN_SCOPE).then((x) => x.data),
    refetchInterval: 15_000,
  });
}

export function useDataset(datasetId: string | null) {
  return useQuery({
    queryKey: ['dataset', datasetId],
    queryFn: () =>
      datasetId
        ? api<Dataset>(`/datasets/${encodeURIComponent(datasetId)}`, OIRAN_SCOPE).then(
            (x) => x.data,
          )
        : Promise.reject(new Error('no-dataset')),
    enabled: !!datasetId,
    staleTime: 30_000,
  });
}

export function useDatasetSessions(datasetId: string | null) {
  return useQuery({
    queryKey: ['dataset-sessions', datasetId],
    queryFn: () =>
      datasetId
        ? api<Session[]>(
            `/datasets/${encodeURIComponent(datasetId)}/sessions?page_size=500`,
            OIRAN_SCOPE,
          ).then((x) => x.data)
        : Promise.reject(new Error('no-dataset')),
    enabled: !!datasetId,
    staleTime: 15_000,
  });
}

export function useUes() {
  return useQuery({
    queryKey: ['ues'],
    queryFn: () =>
      api<UeContext[]>('/ues?page_size=500', OIRAN_SCOPE).then((x) => x.data),
    refetchInterval: 15_000,
  });
}

export function useUe(ueContextId: string | null) {
  return useQuery({
    queryKey: ['ue', ueContextId],
    queryFn: () =>
      ueContextId
        ? api<UeContext>(
            `/ues/${encodeURIComponent(ueContextId)}`,
            OIRAN_SCOPE,
          ).then((x) => x.data)
        : Promise.reject(new Error('no-ue')),
    enabled: !!ueContextId,
  });
}

export function useUeSessions(ueContextId: string | null) {
  return useQuery({
    queryKey: ['ue-sessions', ueContextId],
    queryFn: () =>
      ueContextId
        ? api<Session[]>(
            `/ues/${encodeURIComponent(ueContextId)}/sessions?page_size=200`,
            OIRAN_SCOPE,
          ).then((x) => x.data)
        : Promise.reject(new Error('no-ue')),
    enabled: !!ueContextId,
  });
}

export function useSession(sessionId: string | null) {
  return useQuery({
    queryKey: ['session', sessionId],
    queryFn: () =>
      sessionId
        ? api<Session>(
            `/sessions/${encodeURIComponent(sessionId)}`,
            OIRAN_SCOPE,
          ).then((x) => x.data)
        : Promise.reject(new Error('no-session')),
    enabled: !!sessionId,
  });
}

export function useSessionCallFlow(sessionId: string | null) {
  return useQuery({
    queryKey: ['session-callflow', sessionId],
    queryFn: () =>
      sessionId
        ? api<CallFlow>(
            `/sessions/${encodeURIComponent(sessionId)}/callflow`,
            OIRAN_SCOPE,
          ).then((x) => x.data)
        : Promise.reject(new Error('no-session')),
    enabled: !!sessionId,
    staleTime: 30_000,
  });
}

export function useSessionEvents(sessionId: string | null) {
  return useQuery({
    queryKey: ['session-events', sessionId],
    queryFn: () =>
      sessionId
        ? api<CallFlowEvent[]>(
            `/sessions/${encodeURIComponent(sessionId)}/events?page_size=1000`,
            OIRAN_SCOPE,
          ).then((x) => x.data)
        : Promise.reject(new Error('no-session')),
    enabled: !!sessionId,
  });
}

export function useSessionCorrelations(sessionId: string | null) {
  return useQuery({
    queryKey: ['session-correlations', sessionId],
    queryFn: () =>
      sessionId
        ? api<CorrelationEdge[]>(
            `/sessions/${encodeURIComponent(sessionId)}/correlations?page_size=1000`,
            OIRAN_SCOPE,
          ).then((x) => x.data)
        : Promise.reject(new Error('no-session')),
    enabled: !!sessionId,
  });
}

export type PacketsPage = {
  items: Packet[];
  page: number;
  pageSize: number;
  total: number | null;
  totalPages: number | null;
  totalUnknown: boolean;
};

export const DEFAULT_PACKETS_PAGE_SIZE = 50;

export function usePackets({
  page,
  pageSize = DEFAULT_PACKETS_PAGE_SIZE,
  captureId,
  sessionId,
}: {
  page: number;
  pageSize?: number;
  captureId?: string;
  sessionId?: string;
}) {
  return useQuery<PacketsPage>({
    queryKey: ['packets', page, pageSize, captureId ?? '', sessionId ?? ''],
    queryFn: async () => {
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(pageSize),
      });
      if (captureId) params.set('capture_id', captureId);
      if (sessionId) params.set('session_id', sessionId);
      const envelope: ApiEnvelope<Packet[]> = await api<Packet[]>(
        `/packets?${params}`,
        OIRAN_SCOPE,
      );
      const meta = envelope.meta ?? {};
      const total = typeof meta.total === 'number' ? meta.total : null;
      const totalPages =
        typeof meta.total_pages === 'number'
          ? meta.total_pages
          : total != null
            ? Math.max(1, Math.ceil(total / pageSize))
            : null;
      return {
        items: envelope.data,
        page,
        pageSize,
        total,
        totalPages,
        totalUnknown: total == null,
      };
    },
    placeholderData: (prev) => prev,
  });
}

export function usePacket(packetId: string | null) {
  return useQuery({
    queryKey: ['packet', packetId],
    queryFn: () =>
      packetId
        ? api<Packet>(
            `/packets/${encodeURIComponent(packetId)}`,
            OIRAN_SCOPE,
          ).then((x) => x.data)
        : Promise.reject(new Error('no-packet')),
    enabled: !!packetId,
  });
}
