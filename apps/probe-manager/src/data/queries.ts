import { useQuery } from '@tanstack/react-query';
import { api } from '@shared/api';
import type {
  AuthState,
  Capture,
  CaptureInterface,
  DiskSafety,
  Metrics,
  Probe,
} from '@shared/types';

export function useProbes() {
  return useQuery({
    queryKey: ['probes'],
    queryFn: () => api<Probe[]>('/probes').then((x) => x.data),
    refetchInterval: 5_000,
  });
}

export function useInterfaces() {
  return useQuery({
    queryKey: ['interfaces'],
    queryFn: () => api<CaptureInterface[]>('/interfaces').then((x) => x.data),
    refetchInterval: 7_000,
  });
}

export function useCaptures() {
  return useQuery({
    queryKey: ['captures'],
    queryFn: () =>
      api<Capture[]>('/captures?page_size=200').then((x) => x.data),
    refetchInterval: 4_000,
  });
}

export function useDiskSafety() {
  return useQuery({
    queryKey: ['storage-safety'],
    queryFn: () => api<DiskSafety>('/storage/safety').then((x) => x.data),
    refetchInterval: 10_000,
  });
}

export function useMetrics() {
  return useQuery({
    queryKey: ['metrics'],
    queryFn: () => api<Metrics>('/metrics').then((x) => x.data),
    refetchInterval: 5_000,
  });
}

export function useAuth() {
  return useQuery({
    queryKey: ['auth'],
    queryFn: () => api<AuthState>('/auth/me').then((x) => x.data),
    refetchInterval: 15_000,
    retry: false,
  });
}
