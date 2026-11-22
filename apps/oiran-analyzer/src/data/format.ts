// Formatting helpers that always surface honest "unavailable" states rather
// than fabricating zeros.

export function bytes(value: number | null | undefined): string {
  if (value == null) return 'Not available';
  if (value >= 1024 ** 4) return `${(value / 1024 ** 4).toFixed(2)} TiB`;
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(2)} GiB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(2)} MiB`;
  if (value >= 1024) return `${(value / 1024).toFixed(2)} KiB`;
  return `${value} B`;
}

export function bits(value: number | null | undefined): string {
  if (value == null) return 'Not available';
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(2)} Gbit/s`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)} Mbit/s`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(2)} kbit/s`;
  return `${value} bit/s`;
}

export function pps(value: number | null | undefined): string {
  if (value == null) return 'Not available';
  return `${value.toFixed(2)} pps`;
}

export function percent(value: number | null | undefined): string {
  if (value == null) return '—';
  return `${value.toFixed(1)}%`;
}

export function count(value: number | null | undefined): string {
  if (value == null) return 'Not available';
  return value.toLocaleString();
}

export function epochToLocal(value: number | null | undefined): string {
  if (!value) return '—';
  return new Date(value * 1000).toLocaleString();
}

export function isoToLocal(value: string | null | undefined): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

export function durationSeconds(
  start: string | number | null | undefined,
  end: string | number | null | undefined,
): string {
  if (start == null) return '—';
  const startMs =
    typeof start === 'number' ? start * 1000 : new Date(start).getTime();
  const endMs =
    end == null
      ? Date.now()
      : typeof end === 'number'
        ? end * 1000
        : new Date(end).getTime();
  if (Number.isNaN(startMs) || Number.isNaN(endMs)) return '—';
  const seconds = Math.max(0, Math.floor((endMs - startMs) / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}
