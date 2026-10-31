// Lab defaults for the SST / SD / DNN selectors.
//
// Both forms (Edit and Generate) ALWAYS send sst, sd and dnns explicitly so
// the backend never has to pick a default on behalf of the UI. Values below
// are the ones already served by the lab per /plmns and /dnns at the time
// of 0.17.0, used only as the pre-selected rows when the DNN inventory is
// still loading.

export const LAB_DEFAULT_SST = 1;
export const LAB_DEFAULT_SD: string | null = '010203';
export const LAB_DEFAULT_DNNS: readonly string[] = ['internet'];

export const LAB_SST_OPTIONS: ReadonlyArray<{ value: number; label: string; hint?: string }> = [
  { value: 1, label: '1 — eMBB', hint: 'Enhanced Mobile Broadband' },
  { value: 2, label: '2 — URLLC', hint: 'Ultra-Reliable Low-Latency' },
  { value: 3, label: '3 — mIoT', hint: 'Massive IoT' },
  { value: 4, label: '4 — V2X' },
];

export const LAB_SD_OPTIONS: ReadonlyArray<{ value: string | null; label: string }> = [
  { value: '010203', label: '010203 (lab default)' },
  { value: '000001', label: '000001' },
  { value: '000002', label: '000002' },
  { value: null, label: 'absent' },
];

export const LAB_AMBR_DEFAULT = { uplink: 1_000_000, downlink: 1_000_000 };

export function sanitizeSd(raw: string): string | null {
  if (raw === '' || raw.toLowerCase() === 'null' || raw === 'absent') return null;
  return raw;
}
