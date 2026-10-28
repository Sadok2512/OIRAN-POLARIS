// Local UE Profile model.
//
// The POLARIS Rust backend does not yet expose a profile-CRUD contract
// (see docs/frontend/SIMULATOR_SCENARIO_BUILDER.md). Until it does,
// operator-authored profiles live client-side and are reconciled against
// the backend UE inventory by `id`.
//
// This file holds pure data + validation. No I/O.

export interface UeProfileDraft {
  id: string;
  owner: string;
  servingGnb: string;
  imsi?: string;
  plmn?: string;
  apn?: string;
  ueIp?: string;
  notes?: string;
}

export interface UeProfileRecord extends UeProfileDraft {
  createdAt: number;
  updatedAt: number;
  /** When true, this profile was synthesized from the backend UE inventory and never persisted. */
  derived?: boolean;
  /** Backend mode only: Open5GS provisioning status reported by POLARIS. */
  subscriptionStatus?: string;
  /** Backend mode only: scenario assigned on the profile itself. */
  scenarioId?: string | null;
}

export const MAX_PROFILES = 10_000;

const ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const IMSI_RE = /^\d{14,16}$/;
const PLMN_RE = /^\d{5,6}$/;
const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
const APN_RE = /^[A-Za-z0-9._-]{1,63}$/;

export interface ProfileIssue {
  path: keyof UeProfileDraft;
  message: string;
}

export function validateProfile(draft: UeProfileDraft): ProfileIssue[] {
  const issues: ProfileIssue[] = [];
  if (!draft.id.trim()) {
    issues.push({ path: 'id', message: 'UE ID is required' });
  } else if (!ID_RE.test(draft.id)) {
    issues.push({
      path: 'id',
      message: 'UE ID must be 1–64 chars (letters, digits, _ . : -)',
    });
  }
  if (!draft.owner.trim()) {
    issues.push({ path: 'owner', message: 'Owner is required' });
  }
  if (!draft.servingGnb.trim()) {
    issues.push({ path: 'servingGnb', message: 'Serving gNB is required' });
  }
  if (draft.imsi && !IMSI_RE.test(draft.imsi)) {
    issues.push({ path: 'imsi', message: 'IMSI must be 14–16 digits' });
  }
  if (draft.plmn && !PLMN_RE.test(draft.plmn)) {
    issues.push({ path: 'plmn', message: 'PLMN must be 5 or 6 digits' });
  }
  if (draft.ueIp && !IPV4_RE.test(draft.ueIp)) {
    issues.push({ path: 'ueIp', message: 'UE IP must be an IPv4 address' });
  }
  if (draft.apn && !APN_RE.test(draft.apn)) {
    issues.push({ path: 'apn', message: 'APN must be 1–63 chars (letters, digits, _ . -)' });
  }
  return issues;
}

export function emptyProfile(id = ''): UeProfileDraft {
  return {
    id,
    owner: '',
    servingGnb: '',
    imsi: '',
    plmn: '',
    apn: '',
    ueIp: '',
    notes: '',
  };
}

/* -------------------------------- CSV I/O -------------------------------- */

const CSV_FIELDS: (keyof UeProfileDraft)[] = [
  'id',
  'owner',
  'servingGnb',
  'imsi',
  'plmn',
  'apn',
  'ueIp',
  'notes',
];

export function toCsv(profiles: UeProfileRecord[]): string {
  const header = CSV_FIELDS.join(',');
  const rows = profiles.map((profile) =>
    CSV_FIELDS.map((field) => csvEscape(profile[field] ?? '')).join(','),
  );
  return [header, ...rows].join('\n');
}

export interface CsvParseResult {
  profiles: UeProfileDraft[];
  errors: { line: number; message: string }[];
}

export function parseCsv(text: string): CsvParseResult {
  const result: CsvParseResult = { profiles: [], errors: [] };
  const lines = splitCsvLines(text);
  if (lines.length === 0) return result;
  const header = parseCsvLine(lines[0]).map((cell) => cell.trim());
  const index: Partial<Record<keyof UeProfileDraft, number>> = {};
  CSV_FIELDS.forEach((field) => {
    const i = header.indexOf(field);
    if (i >= 0) index[field] = i;
  });
  if (index.id == null) {
    result.errors.push({
      line: 1,
      message: 'CSV header must contain an "id" column',
    });
    return result;
  }
  for (let i = 1; i < lines.length; i += 1) {
    const raw = lines[i];
    if (raw.trim() === '') continue;
    const cells = parseCsvLine(raw);
    const draft = emptyProfile();
    (Object.keys(index) as (keyof UeProfileDraft)[]).forEach((field) => {
      const col = index[field];
      if (col == null) return;
      draft[field] = (cells[col] ?? '').trim();
    });
    const issues = validateProfile(draft);
    if (issues.length > 0) {
      result.errors.push({
        line: i + 1,
        message: issues.map((issue) => `${issue.path}: ${issue.message}`).join('; '),
      });
      continue;
    }
    result.profiles.push(draft);
  }
  return result;
}

function csvEscape(value: string): string {
  if (/[",\n\r]/.test(value)) return `"${value.replace(/"/g, '""')}"`;
  return value;
}

function splitCsvLines(text: string): string[] {
  const normalized = text.replace(/\r\n?/g, '\n');
  const lines: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < normalized.length; i += 1) {
    const ch = normalized[i];
    if (ch === '"') {
      current += ch;
      inQuotes = !inQuotes;
      // Handle escaped quote inside quotes ("")
      if (inQuotes === false && normalized[i + 1] === '"') {
        current += '"';
        inQuotes = true;
        i += 1;
      }
      continue;
    }
    if (ch === '\n' && !inQuotes) {
      lines.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.length > 0) lines.push(current);
  return lines;
}

function parseCsvLine(line: string): string[] {
  const cells: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i += 1;
        continue;
      }
      inQuotes = !inQuotes;
      continue;
    }
    if (ch === ',' && !inQuotes) {
      cells.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  cells.push(current);
  return cells;
}

/* -------------------------- Bulk create generator -------------------------- */

export interface BulkCreateSpec {
  count: number;
  prefix: string;
  startIndex: number;
  padWidth: number;
  owner: string;
  servingGnb: string;
  plmn?: string;
  apn?: string;
  imsiBase?: string;
}

export interface BulkCreateResult {
  profiles: UeProfileDraft[];
  errors: string[];
}

export function generateBulk(spec: BulkCreateSpec): BulkCreateResult {
  const errors: string[] = [];
  const profiles: UeProfileDraft[] = [];
  if (!Number.isInteger(spec.count) || spec.count < 1) {
    errors.push('Count must be a positive integer');
    return { profiles, errors };
  }
  if (spec.count > MAX_PROFILES) {
    errors.push(`Count exceeds ${MAX_PROFILES.toLocaleString()} profiles limit`);
    return { profiles, errors };
  }
  if (!spec.prefix.trim()) {
    errors.push('Prefix is required');
    return { profiles, errors };
  }
  if (!spec.owner.trim()) {
    errors.push('Owner is required');
    return { profiles, errors };
  }
  if (!spec.servingGnb.trim()) {
    errors.push('Serving gNB is required');
    return { profiles, errors };
  }
  const start = Number.isInteger(spec.startIndex) ? spec.startIndex : 1;
  const pad = Math.max(1, spec.padWidth || 1);
  const imsiBase = spec.imsiBase?.trim();
  if (imsiBase && !/^\d{10,15}$/.test(imsiBase)) {
    errors.push('IMSI base must be 10–15 digits (an offset is appended)');
    return { profiles, errors };
  }
  for (let i = 0; i < spec.count; i += 1) {
    const n = start + i;
    const suffix = n.toString().padStart(pad, '0');
    const id = `${spec.prefix.trim()}${suffix}`;
    if (!ID_RE.test(id)) {
      errors.push(`Generated id "${id}" is not a valid UE id`);
      return { profiles: [], errors };
    }
    const imsi = imsiBase
      ? (imsiBase + suffix).slice(-15)
      : '';
    profiles.push({
      id,
      owner: spec.owner.trim(),
      servingGnb: spec.servingGnb.trim(),
      imsi,
      plmn: spec.plmn?.trim() ?? '',
      apn: spec.apn?.trim() ?? '',
      ueIp: '',
      notes: '',
    });
  }
  return { profiles, errors };
}
