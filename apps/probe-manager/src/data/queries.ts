import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type ApiOptions } from '@shared/api';
import type {
  ApiEnvelope,
  AuthState,
  Capture,
  CaptureInterface,
  DiskSafety,
  Metrics,
  Probe,
  CaptureRequest,
} from '@shared/types';

// The Probe Manager is an OIRAN consumer. Every request names the OIRAN
// auth scope so the shared client knows which token (if any) to attach.
// POLARIS-scoped tokens are never attached to these requests.
const OIRAN_SCOPE: ApiOptions = { authScope: 'oiran' };

export function useProbes() {
  return useQuery({
    queryKey: ['probes'],
    queryFn: () => api<Probe[]>('/probes', OIRAN_SCOPE).then((x) => x.data),
    refetchInterval: 5_000,
  });
}

export function useInterfaces() {
  return useQuery({
    queryKey: ['interfaces'],
    queryFn: () =>
      api<CaptureInterface[]>('/interfaces', OIRAN_SCOPE).then((x) => x.data),
    refetchInterval: 7_000,
  });
}

export type CapturesPage = {
  items: Capture[];
  page: number;
  pageSize: number;
  total: number | null;
  totalPages: number | null;
  /**
   * Honest flag: true when the backend did not echo meta.total or
   * meta.total_pages, so the UI must display a partial-results notice
   * instead of pretending it loaded everything. See PR #2 Section 4.
   */
  totalUnknown: boolean;
};

export const DEFAULT_CAPTURE_PAGE_SIZE = 25;

async function fetchCapturesPage(
  page: number,
  pageSize: number,
): Promise<CapturesPage> {
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
  });
  const envelope: ApiEnvelope<Capture[]> = await api<Capture[]>(
    `/captures?${params}`,
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
}

/**
 * Paginated hook used by the Capture Library. Honors the backend's
 * `meta.total` / `meta.total_pages` when provided; otherwise sets
 * `totalUnknown=true` so the UI can show a partial-results warning.
 */
export function useCapturesPage({
  page,
  pageSize = DEFAULT_CAPTURE_PAGE_SIZE,
}: {
  page: number;
  pageSize?: number;
}) {
  return useQuery<CapturesPage>({
    queryKey: ['captures-page', page, pageSize],
    queryFn: () => fetchCapturesPage(page, pageSize),
    placeholderData: (previous) => previous,
    refetchInterval: 4_000,
  });
}

/**
 * Legacy "first page" hook kept for Overview / Probes / Interfaces /
 * Live Captures views, which only need a representative slice of
 * captures to compute counters, show the active job, or list jobs
 * related to a selected probe/interface. For paginated navigation use
 * `useCapturesPage` instead.
 */
export function useCaptures(pageSize = 100) {
  return useQuery<CapturesPage>({
    queryKey: ['captures-first-page', pageSize],
    queryFn: () => fetchCapturesPage(1, pageSize),
    refetchInterval: 4_000,
  });
}

export function useDiskSafety() {
  return useQuery({
    queryKey: ['storage-safety'],
    queryFn: () =>
      api<DiskSafety>('/storage/safety', OIRAN_SCOPE).then((x) => x.data),
    refetchInterval: 10_000,
  });
}

export function useMetrics() {
  return useQuery({
    queryKey: ['metrics'],
    queryFn: () => api<Metrics>('/metrics', OIRAN_SCOPE).then((x) => x.data),
    refetchInterval: 5_000,
  });
}

export function useAuth() {
  return useQuery({
    queryKey: ['auth'],
    queryFn: () =>
      api<AuthState>('/auth/me', OIRAN_SCOPE).then((x) => x.data),
    refetchInterval: 15_000,
    retry: false,
  });
}

type ValidationResult = {
  authorization: string;
  validation: { valid?: boolean; errors?: string[]; warnings?: string[] };
};

export function useValidateCapture() {
  return useMutation({
    mutationFn: (request: CaptureRequest) =>
      api<ValidationResult>('/captures/validate', {
        ...OIRAN_SCOPE,
        method: 'POST',
        body: JSON.stringify(request),
      }).then((result) => result.data),
  });
}

export function useStartCapture() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (request: CaptureRequest) =>
      api<Capture>('/captures/start', {
        ...OIRAN_SCOPE,
        method: 'POST',
        body: JSON.stringify(request),
      }).then((result) => result.data),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['captures-first-page'] });
      await client.invalidateQueries({ queryKey: ['captures-page'] });
    },
  });
}

export function useStopCapture() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (captureId: string) =>
      api<Capture>(`/captures/${encodeURIComponent(captureId)}/stop`, {
        ...OIRAN_SCOPE,
        method: 'POST',
      }).then((result) => result.data),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['captures-first-page'] });
      await client.invalidateQueries({ queryKey: ['captures-page'] });
    },
  });
}
