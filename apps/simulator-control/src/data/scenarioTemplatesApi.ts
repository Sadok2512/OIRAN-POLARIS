// 0.5.0 — client for the scenario-template surface published by Codex on
// `feat/polaris-traffic-templates`. The contract is NOT shipped yet;
// every hook here is gated by the `scenarioTemplates` feature flag. API 0.13
// enables it by default; an operator can still disable the surface in Settings.
//
// Routes (contract from the LOT prompt):
//   GET  /api/v1/scenario-definitions                      (tpl-* appear here)
//   GET  /api/v1/scenario-definitions/:id/estimate         → { duration_ms }
//   GET  /api/v1/scenario-definitions/:id/export           → attachment JSON v2
//   POST /api/v1/scenario-definitions/import               operator + CSRF
//        query: ?mode=new_version | ?rename=<id>
//        errors: 409 SCENARIO_ID_EXISTS | TEMPLATE_ID_RESERVED,
//                413 IMPORT_PAYLOAD_TOO_LARGE,
//                422 SCHEMA_UNKNOWN / <scenario-level codes>

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '@shared/api';
import { polarisApi } from './polarisClient';
import { useFeatureFlag } from './featureFlags';
import {
  SCENARIO_SCHEMA_VERSION,
  type WireScenarioDefinition,
  type WireScenarioDefinitionList,
  type WireScenarioExportFile,
} from '@/scenarios/wireCodec';

/** Marker prefix for read-only, backend-seeded templates. */
export const TEMPLATE_ID_PREFIX = 'tpl-';

export function isTemplateId(id: string | null | undefined): boolean {
  return !!id && id.startsWith(TEMPLATE_ID_PREFIX);
}

export interface TemplateEstimate {
  duration_ms: number;
}

/** List of definitions, filtered client-side to templates (tpl-*). */
export function useScenarioTemplates() {
  const enabled = useFeatureFlag('scenarioTemplates');
  return useQuery({
    queryKey: ['polaris', 'scenario-templates'],
    queryFn: async () => {
      const body = await polarisApi<WireScenarioDefinitionList>('/scenario-definitions');
      const templates = (body.items ?? []).filter((item) => isTemplateId(item.id));
      return { items: templates, total: templates.length, schema_version: body.schema_version };
    },
    enabled,
    staleTime: enabled ? 30_000 : Infinity,
  });
}

/** Backend-computed duration estimate for a given definition (templates or user-authored). */
export function useScenarioEstimate(id: string | null) {
  const enabled = useFeatureFlag('scenarioTemplates') && !!id;
  return useQuery({
    queryKey: ['polaris', 'scenario-estimate', id],
    queryFn: () => polarisApi<TemplateEstimate>(`/scenario-definitions/${id}/estimate`),
    enabled,
    staleTime: 60_000,
    retry: false,
  });
}

/**
 * `GET /scenario-definitions/:id/export` — returns the full WireScenarioExportFile
 * body AND the backend-suggested filename extracted from `Content-Disposition`.
 * Falls back to `<id>-v<version>.json` when the backend did not advertise one.
 */
export interface DownloadedExport {
  payload: WireScenarioExportFile;
  filename: string;
}

export async function downloadScenarioExport(id: string): Promise<DownloadedExport> {
  const response = await fetch(`/polaris-api/v1/scenario-definitions/${id}/export`, {
    headers: { Accept: 'application/json' },
    credentials: 'same-origin',
  });
  if (!response.ok) {
    let code = 'EXPORT_FAILED';
    try {
      const body = (await response.json()) as { error?: string | { code?: string } };
      if (typeof body.error === 'string') code = body.error;
      else if (body.error && typeof body.error === 'object' && body.error.code) code = body.error.code;
    } catch {
      // Keep the generic code.
    }
    throw new ApiError(response.status, code, `HTTP ${response.status} ${code}`);
  }
  const payload = (await response.json()) as WireScenarioExportFile;
  if (payload.schema_version !== SCENARIO_SCHEMA_VERSION) {
    throw new ApiError(422, 'SCHEMA_UNKNOWN', `unexpected schema_version ${payload.schema_version}`);
  }
  const disposition = response.headers.get('content-disposition') ?? '';
  const filename = parseFilename(disposition) ?? defaultFilename(payload.definition);
  return { payload, filename };
}

function parseFilename(disposition: string): string | null {
  const match = /filename="?([^";]+)"?/i.exec(disposition);
  return match ? match[1] : null;
}

export function defaultFilename(definition: WireScenarioDefinition): string {
  const version = typeof definition.version === 'number' ? definition.version : 1;
  const safeId = definition.id.replace(/[^a-z0-9.-]/gi, '_');
  return `${safeId}-v${version}.json`;
}

/**
 * Import mode:
 *   • `new_version` keeps the id, bumps the backend version counter;
 *   • `rename` sends a fresh id, lets the backend validate it.
 * When no mode is passed, the backend rejects collisions with 409.
 */
export type ImportMode =
  | { kind: 'reject-collision' }
  | { kind: 'new_version' }
  | { kind: 'rename'; target_id: string };

export function useScenarioImport() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async ({ file, mode }: { file: WireScenarioExportFile; mode: ImportMode }) => {
      if (file.schema_version !== SCENARIO_SCHEMA_VERSION) {
        throw new ApiError(422, 'SCHEMA_UNKNOWN', `local schema check: expected ${SCENARIO_SCHEMA_VERSION}`);
      }
      const query =
        mode.kind === 'new_version'
          ? '?mode=new_version'
          : mode.kind === 'rename'
            ? `?rename=${encodeURIComponent(mode.target_id)}`
            : '';
      return polarisApi<WireScenarioDefinition>(`/scenario-definitions/import${query}`, {
        method: 'POST',
        body: JSON.stringify(file),
      });
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-definitions'] });
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-templates'] });
    },
  });
}
