import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Copy,
  Download,
  Edit,
  Plus,
  Search,
  StopCircle,
  Trash2,
  Upload,
  Users,
} from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { ErrorState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import { ConfirmDialog } from '@/ui/ConfirmDialog';
import {
  useAuth,
  useStartScenario,
  useStartUe,
  useStopScenario,
  useStopUe,
  useScenarioRuntime,
  useUes,
} from '@/data/queries';
import { useAssignments } from '@/scenarios/store';
import { useScenarioLibrary } from '@/scenarios/library';
import { certifiedProfileFor, type Scenario } from '@/scenarios/model';
import type { UeState } from '@/data/polarisTypes';
import {
  parseCsv,
  toCsv,
  type UeProfileDraft,
  type UeProfileRecord,
} from '@/ue/profileModel';
import {
  bulkCreateProfiles,
  cloneProfile,
  createProfile,
  deleteProfiles,
  paginate,
  updateProfile,
  useProfiles,
} from '@/ue/profileStore';
import { UeProfileFormDialog, type ProfileFormMode } from '@/ue/UeProfileForm';
import { UeProfileBackendFormDialog } from '@/ue/UeProfileBackendForm';
import { UeProvisioningAddDialog, type UeProvisioningAddValues } from '@/ue/UeProvisioningAddDialog';
import { useBackendProfiles } from '@/ue/profileSource';
import { fetchGnbs, type WireGnb, type WireUeProfileMutation } from '@/data/profileApi';
import { useFeatureFlag } from '@/data/featureFlags';
import { createUeProvisioningProfile, useOwners } from '@/data/provisioningApi';
import { ApiError } from '@shared/api';
import { useStartScenarioRun } from '@/data/scenarioApi';
import { UeBulkCreateDialog } from '@/ue/UeBulkCreateDialog';
import { AssignScenarioDialog } from '@/ue/AssignScenarioDialog';
import { CsvImportDialog } from '@/components/CsvImportDialog';
import { useQuery } from '@tanstack/react-query';

const PAGE_SIZES = [25, 50, 100, 250] as const;

interface MergedRow {
  profile: UeProfileRecord;
  backend?: UeState;
}

export function UeManagerPage() {
  const auth = useAuth();
  const uesQuery = useUes();
  const library = useScenarioLibrary();
  const assignments = useAssignments();
  const runtime = useScenarioRuntime();
  const startScenario = useStartScenario();
  const stopScenario = useStopScenario();
  const startUe = useStartUe();
  const stopUe = useStopUe();

  const backendProfiles = useBackendProfiles();
  const profileBackend = backendProfiles.enabled;
  const localProfiles = useProfiles();
  const profiles = profileBackend ? backendProfiles.profiles : localProfiles;
  const scenarioBackend = useFeatureFlag('scenarioBackend');
  const startDefinitionRun = useStartScenarioRun();

  const [search, setSearch] = useState('');
  const [ownerFilter, setOwnerFilter] = useState('');
  const [gnbFilter, setGnbFilter] = useState('');
  const [pageSize, setPageSize] = useState<number>(50);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [feedback, setFeedback] = useState('');

  const [formState, setFormState] = useState<{
    mode: ProfileFormMode;
    initial?: UeProfileDraft;
  } | null>(null);
  const polarisProvisioning = useFeatureFlag('polarisProvisioning');
  const [provisioningAddOpen, setProvisioningAddOpen] = useState(false);
  const [provisioningAddError, setProvisioningAddError] = useState<string | null>(null);
  const [provisioningAddSubmitting, setProvisioningAddSubmitting] = useState(false);
  const [backendCsvOpen, setBackendCsvOpen] = useState(false);
  // The gNB directory is already published by polaris-control-api 0.11.0;
  // reuse the hook to feed the Add UE dropdown. We ping the owner directory
  // under the polarisProvisioning flag so the hook stays off when the
  // backend branch is not yet deployed.
  const gnbList = useQuery({
    queryKey: ['polaris', 'gnbs'],
    queryFn: fetchGnbs,
    enabled: polarisProvisioning,
    retry: false,
    staleTime: 60_000,
  });
  const ownerList = useOwners();
  const [bulkOpen, setBulkOpen] = useState(false);
  const [assignOpen, setAssignOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string[] | null>(null);
  const [confirmStop, setConfirmStop] = useState<MergedRow | null>(null);
  const [confirmRun, setConfirmRun] = useState<{ row: MergedRow; scenario: Scenario } | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const canOperate = auth.data?.can_start === true;

  // Reset selection when the filter set changes.
  useEffect(() => {
    setSelected(new Set());
  }, [search, ownerFilter, gnbFilter, profiles.length]);

  // Backend UE inventory indexed for O(1) lookup.
  const backendByProfileId = useMemo(() => {
    const map = new Map<string, UeState>();
    for (const ue of uesQuery.data?.items ?? []) {
      map.set(ue.id, ue);
    }
    return map;
  }, [uesQuery.data?.items]);

  const assignmentByUe = useMemo(() => {
    if (profileBackend) {
      return new Map(
        profiles
          .filter((profile) => profile.scenarioId)
          .map((profile) => [
            profile.id,
            {
              ueId: profile.id,
              scenarioId: profile.scenarioId as string,
              autoRun: backendProfiles.wireById.get(profile.id)?.auto_run_scenario ?? false,
              updatedAt: profile.updatedAt,
            },
          ]),
      );
    }
    return new Map(assignments.assignments.map((assignment) => [assignment.ueId, assignment]));
  }, [profileBackend, profiles, backendProfiles.wireById, assignments.assignments]);

  async function setBackendAssignment(ueIds: string[], scenarioId: string | null, autoRun: boolean) {
    const failures = await backendProfiles.assign(ueIds, scenarioId, autoRun);
    if (failures.length > 0) setFeedback(`Assignment failed · ${failures.join(' · ')}`);
    return failures;
  }

  const scenarioById = useMemo(
    () => new Map(library.scenarios.map((scenario) => [scenario.id, scenario])),
    [library.scenarios],
  );

  const ownerOptions = useMemo(() => uniqueSorted(profiles.map((profile) => profile.owner)), [profiles]);
  const gnbOptions = useMemo(
    () => uniqueSorted(profiles.map((profile) => profile.servingGnb)),
    [profiles],
  );

  const paged = useMemo(
    () =>
      paginate(profiles, {
        search,
        owner: ownerFilter,
        servingGnb: gnbFilter,
        page,
        pageSize,
        sortBy: 'id',
        sortDirection: 'asc',
      }),
    [profiles, search, ownerFilter, gnbFilter, page, pageSize],
  );

  // Clamp page if filter shrinks the result set.
  useEffect(() => {
    if (page > paged.pageCount) setPage(paged.pageCount);
  }, [paged.pageCount, page]);

  const rows: MergedRow[] = useMemo(
    () =>
      paged.items.map((profile) => ({
        profile,
        backend: backendByProfileId.get(profile.id),
      })),
    [paged.items, backendByProfileId],
  );

  const selectedProfiles = useMemo(
    () => profiles.filter((profile) => selected.has(profile.id)),
    [profiles, selected],
  );

  const activeJob = runtime.data?.active_job;

  /* ----------------------------- Mutators ------------------------------ */

  // 0.7.1 — polarisProvisioning Add UE flow. The backend accepts
  // exactly {ue_id, gnb_id, owner, note, imsi}; `createUeProvisioningProfile`
  // serialises those five fields and NOTHING ELSE so the 0.11-era
  // carriers (k, opc, keep_identity, plmn_mcc, plmn_mnc, dnn, sst, sd,
  // scenario_id, auto_run_scenario, provisioning_slot) never leak and
  // AUTHENTICATION_KEY_REQUIRED can never be caused by this UI.
  async function submitProvisioningAdd(values: UeProvisioningAddValues) {
    setProvisioningAddError(null);
    setProvisioningAddSubmitting(true);
    try {
      await createUeProvisioningProfile(values);
      setProvisioningAddOpen(false);
      setFeedback(
        `UE ${values.ue_id} created on POLARIS (owner: ${values.owner}, gNB: ${values.gnb_id}).`,
      );
    } catch (error) {
      const code = error instanceof ApiError ? error.code : 'UE_CREATE_FAILED';
      const status = error instanceof ApiError ? error.status : null;
      setProvisioningAddError(
        `${status ? `HTTP ${status} · ` : ''}${code} · ${(error as Error).message}`,
      );
    } finally {
      setProvisioningAddSubmitting(false);
    }
  }

  async function submitBackend(body: WireUeProfileMutation, mode: ProfileFormMode) {
    if (mode === 'create') {
      await backendProfiles.create(body);
      setFeedback(`Profile ${body.ue_id} created on POLARIS.`);
    } else if (mode === 'edit' && formState?.initial) {
      await backendProfiles.update(formState.initial.id, { ...body, ue_id: formState.initial.id });
      setFeedback(`Profile ${formState.initial.id} updated on POLARIS.`);
    } else if (mode === 'clone' && formState?.initial) {
      await backendProfiles.clone(formState.initial.id, body.ue_id);
      setFeedback(`Profile ${body.ue_id} cloned from ${formState.initial.id} (not provisioned yet).`);
    }
    setFormState(null);
  }

  async function submitCreate(draft: UeProfileDraft) {
    createProfile(draft);
    setFormState(null);
    setFeedback(`Profile ${draft.id} created.`);
  }

  async function submitEdit(draft: UeProfileDraft) {
    if (!formState || formState.mode !== 'edit' || !formState.initial) return;
    updateProfile(formState.initial.id, draft);
    setFormState(null);
    setFeedback(`Profile ${draft.id} updated.`);
  }

  async function submitClone(draft: UeProfileDraft) {
    if (!formState || formState.mode !== 'clone' || !formState.initial) return;
    cloneProfile(formState.initial.id, draft.id);
    // Carry over any non-id edits the operator made before confirming.
    updateProfile(draft.id, draft);
    setFormState(null);
    setFeedback(`Profile ${draft.id} cloned from ${formState.initial.id}.`);
  }

  async function removeSelected() {
    if (!confirmDelete) return;
    if (profileBackend) {
      const ids = confirmDelete;
      setConfirmDelete(null);
      const result = await backendProfiles.remove(ids);
      setSelected(new Set());
      setFeedback(
        `${result.deleted} profile${result.deleted === 1 ? '' : 's'} deleted on POLARIS.` +
          (result.failures.length > 0 ? ` Failed: ${result.failures.join(' · ')}` : ''),
      );
      return;
    }
    const removed = deleteProfiles(confirmDelete);
    for (const id of confirmDelete) assignments.clear(id);
    setConfirmDelete(null);
    setSelected((prev) => {
      const next = new Set(prev);
      for (const id of confirmDelete) next.delete(id);
      return next;
    });
    setFeedback(`${removed} profile${removed === 1 ? '' : 's'} deleted.`);
  }

  function handleBulk(createdDrafts: UeProfileDraft[]) {
    const result = bulkCreateProfiles(createdDrafts);
    setBulkOpen(false);
    const skipped = result.skipped.length;
    if (result.created === 0) {
      setFeedback(`No profile created · ${result.skipped[0]?.reason ?? 'nothing to add'}.`);
      return;
    }
    setFeedback(
      skipped > 0
        ? `Created ${result.created} profiles. Skipped ${skipped} (${result.skipped[0].reason}).`
        : `Created ${result.created} profiles.`,
    );
  }

  async function handleExport() {
    if (profileBackend) {
      // Sanitized server-side export (no SUPI/K/OPc columns).
      try {
        const response = await fetch('/polaris-api/v1/ue-profiles/export.csv', {
          credentials: 'same-origin',
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `ue-profiles-polaris-${timestampSuffix()}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        setFeedback('Exported the POLARIS profile registry (sanitized CSV).');
      } catch (error) {
        setFeedback(`Export failed · ${(error as Error).message}`);
      }
      return;
    }
    const csv = toCsv(selectedProfiles.length > 0 ? selectedProfiles : profiles);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    const scope = selectedProfiles.length > 0 ? 'selection' : 'all';
    link.download = `ue-profiles-${scope}-${timestampSuffix()}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setFeedback(
      `Exported ${selectedProfiles.length > 0 ? selectedProfiles.length : profiles.length} profile${
        profiles.length === 1 ? '' : 's'
      } to CSV.`,
    );
  }

  async function handleImportFile(file: File) {
    const text = await file.text();
    const parsed = parseCsv(text);
    if (parsed.profiles.length === 0) {
      setFeedback(
        parsed.errors.length > 0
          ? `Import failed · ${parsed.errors.length} invalid row${parsed.errors.length === 1 ? '' : 's'}.`
          : 'Import failed · no valid rows in CSV.',
      );
      return;
    }
    const result = bulkCreateProfiles(parsed.profiles);
    setFeedback(
      `Imported ${result.created} profile${result.created === 1 ? '' : 's'}. Skipped ${
        result.skipped.length
      }${parsed.errors.length > 0 ? ` · ${parsed.errors.length} invalid row(s) ignored` : ''}.`,
    );
  }

  async function handleAssign({ scenarioId, autoRun }: { scenarioId: string | null; autoRun: boolean }) {
    const targetIds = selectedProfiles.map((profile) => profile.id);
    if (targetIds.length === 0) {
      setAssignOpen(false);
      return;
    }
    if (profileBackend) {
      setAssignOpen(false);
      const failures = await setBackendAssignment(targetIds, scenarioId, autoRun);
      if (failures.length === 0) {
        setFeedback(
          scenarioId
            ? `Assigned scenario to ${targetIds.length} UE${targetIds.length === 1 ? '' : 's'} on POLARIS.`
            : `Cleared scenario assignment on ${targetIds.length} UE${targetIds.length === 1 ? '' : 's'}.`,
        );
      }
      return;
    }
    for (const id of targetIds) {
      if (scenarioId) assignments.assign(id, scenarioId, autoRun);
      else assignments.clear(id);
    }
    setAssignOpen(false);
    setFeedback(
      scenarioId
        ? `Assigned scenario to ${targetIds.length} UE${targetIds.length === 1 ? '' : 's'}.`
        : `Cleared scenario assignment on ${targetIds.length} UE${targetIds.length === 1 ? '' : 's'}.`,
    );
  }

  async function runScenarioOn(row: MergedRow, scenario: Scenario) {
    if (scenarioBackend) {
      try {
        const job = await startDefinitionRun.mutateAsync({
          scenario_definition_id: scenario.id,
          ue_ids: [row.profile.id],
        });
        setFeedback(`Scenario ${scenario.name} started for ${row.profile.id} · job ${job.job_id} (${job.state}).`);
      } catch (error) {
        const code = (error as { code?: string }).code;
        setFeedback(
          code === 'SCENARIO_DEFINITION_LIVE_EXECUTION_NOT_AUTHORIZED'
            ? 'Live execution of backend scenario definitions is locked on this controller (mock mode only).'
            : `${code ?? 'Start failed'} · ${(error as Error).message}`,
        );
      }
      return;
    }
    if (!row.backend) {
      setFeedback(`${row.profile.id}: backend has not reported this UE yet — not provisioned.`);
      return;
    }
    const profile = certifiedProfileFor(scenario);
    if (!profile) {
      setFeedback(
        `${scenario.name}: scenario shape is not covered by any certified backend profile yet.`,
      );
      return;
    }
    try {
      await startScenario.mutateAsync({
        scenario_id: `${scenario.id}-${Date.now()}`,
        scenario_type: profile.scenario_type,
        target_ue_id: row.backend.internal_ue_id ?? row.backend.id,
      });
      setFeedback(`Scenario ${scenario.name} dispatched for ${row.profile.id}.`);
    } catch (error) {
      setFeedback((error as Error).message);
    }
  }

  async function stopFor(row: MergedRow) {
    if (!activeJob?.job_id) {
      setFeedback('No active job to stop.');
      return;
    }
    const backendId = row.backend?.internal_ue_id ?? row.backend?.id;
    if (activeJob.target_ue_id && activeJob.target_ue_id !== backendId) {
      setFeedback('Active job is not owned by this UE; stop ignored.');
      return;
    }
    try {
      await stopScenario.mutateAsync(activeJob.job_id);
      setFeedback(`Stop sent for job ${activeJob.job_id}.`);
    } catch (error) {
      setFeedback((error as Error).message);
    }
  }

  async function startBackendUe(row: MergedRow) {
    if (!row.backend?.actions?.start) {
      setFeedback(`${row.profile.id}: backend reports Start not available (${row.backend?.actions?.reason ?? 'not provisioned'}).`);
      return;
    }
    try {
      await startUe.mutateAsync(row.backend.internal_ue_id ?? row.backend.id);
      setFeedback(`Start sent for ${row.profile.id}.`);
    } catch (error) {
      setFeedback((error as Error).message);
    }
  }

  async function stopBackendUe(row: MergedRow) {
    if (!row.backend?.actions?.stop) {
      setFeedback(`${row.profile.id}: backend reports Stop not available.`);
      return;
    }
    try {
      await stopUe.mutateAsync(row.backend.internal_ue_id ?? row.backend.id);
      setFeedback(`Stop sent for ${row.profile.id}.`);
    } catch (error) {
      setFeedback((error as Error).message);
    }
  }

  /* ------------------------------ Render ------------------------------- */

  const pageStart = (paged.page - 1) * paged.pageSize + 1;
  const pageEnd = pageStart + paged.items.length - 1;

  return (
    <>
      <PageHeader
        eyebrow="Operations"
        title="UE Profile Manager"
        description="Operator-authored UE profiles reconciled with the POLARIS backend inventory. Profiles persist in the browser until a backend CRUD contract is available; backend state (registration, PDU, UE IP, traffic) is read live from POLARIS."
        actions={
          <div className="flex items-center gap-2">
            <StatusIndicator
              state={canOperate ? 'OPERATOR_READY' : 'VIEWER_READONLY'}
              tone={canOperate ? 'success' : 'warning'}
              label={canOperate ? 'Operator role active' : 'Viewer — read-only'}
            />
          </div>
        }
      />

      {uesQuery.isLoading && !uesQuery.data && (
        <LoadingSkeleton label="Loading backend UE inventory" />
      )}
      {uesQuery.error && (
        <ErrorState
          title="Could not load backend UE inventory"
          detail={(uesQuery.error as Error).message}
          onRetry={() => void uesQuery.refetch()}
        />
      )}

      <section className="ep-card p-3 mb-3 flex flex-col gap-3" data-testid="ue-toolbar">
        <div className="flex flex-wrap items-center gap-2">
          <label className="relative">
            <Search
              className="absolute left-2 top-1/2 -translate-y-1/2 text-text-secondary"
              width={13}
              height={13}
              aria-hidden="true"
            />
            <input
              className="ep-input pl-7 w-64"
              placeholder="Search id, owner, gNB, IMSI, UE IP…"
              value={search}
              onChange={(event) => {
                setSearch(event.target.value);
                setPage(1);
              }}
              data-testid="ue-search"
            />
          </label>
          <select
            className="ep-input"
            value={ownerFilter}
            onChange={(event) => {
              setOwnerFilter(event.target.value);
              setPage(1);
            }}
            data-testid="ue-filter-owner"
          >
            <option value="">All owners</option>
            {ownerOptions.map((owner) => (
              <option key={owner} value={owner}>
                {owner}
              </option>
            ))}
          </select>
          <select
            className="ep-input"
            value={gnbFilter}
            onChange={(event) => {
              setGnbFilter(event.target.value);
              setPage(1);
            }}
            data-testid="ue-filter-gnb"
          >
            <option value="">All serving gNBs</option>
            {gnbOptions.map((gnb) => (
              <option key={gnb} value={gnb}>
                {gnb}
              </option>
            ))}
          </select>

          <div className="flex-1" />

          <button
            type="button"
            className="ep-button ep-button-sm ep-button-primary"
            onClick={() =>
              polarisProvisioning
                ? setProvisioningAddOpen(true)
                : setFormState({ mode: 'create' })
            }
            disabled={!canOperate}
            data-testid="ue-add"
          >
            <Plus width={13} height={13} />
            Add UE
          </button>
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={() => setBulkOpen(true)}
            disabled={!canOperate || profileBackend}
            title={profileBackend ? 'Bulk via the POLARIS API (10/100/1000/10000) — UI planned for V1.1' : undefined}
            data-testid="ue-bulk"
          >
            <Users width={13} height={13} />
            Bulk create
          </button>
          {polarisProvisioning ? (
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={() => setBackendCsvOpen(true)}
              disabled={!canOperate}
              data-testid="ue-import-backend"
            >
              <Upload width={13} height={13} />
              Import CSV
            </button>
          ) : (
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={() => fileInputRef.current?.click()}
              disabled={!canOperate || profileBackend}
              title={profileBackend ? 'Backend required — POLARIS has no CSV import route' : undefined}
              data-testid="ue-import"
            >
              <Upload width={13} height={13} />
              Import CSV
            </button>
          )}
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv,text/csv"
            hidden
            onChange={(event) => {
              const file = event.target.files?.[0];
              event.target.value = '';
              if (file) void handleImportFile(file);
            }}
            data-testid="ue-import-input"
          />
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={() => void handleExport()}
            disabled={profiles.length === 0}
            data-testid="ue-export"
          >
            <Download width={13} height={13} />
            Export CSV
          </button>
        </div>

        {selected.size > 0 && (
          <div
            className="flex flex-wrap items-center gap-2 border-t border-border pt-3"
            data-testid="ue-bulk-bar"
          >
            <span className="text-ep-sm">
              <span className="font-medium">{selected.size.toLocaleString()}</span> selected
            </span>
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={() => setAssignOpen(true)}
              disabled={!canOperate}
            >
              Assign scenario
            </button>
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={() => {
                for (const profile of selectedProfiles) {
                  const row: MergedRow = { profile, backend: backendByProfileId.get(profile.id) };
                  if (row.backend) void startBackendUe(row);
                }
              }}
              disabled={!canOperate}
              data-testid="ue-bulk-start"
            >
              Start selected
            </button>
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={() => {
                for (const profile of selectedProfiles) {
                  const row: MergedRow = { profile, backend: backendByProfileId.get(profile.id) };
                  if (row.backend) void stopBackendUe(row);
                }
              }}
              disabled={!canOperate}
              data-testid="ue-bulk-stop"
            >
              Stop selected
            </button>
            <button
              type="button"
              className="ep-button ep-button-sm ep-button-danger"
              onClick={() => setConfirmDelete(selectedProfiles.map((profile) => profile.id))}
              disabled={!canOperate}
              data-testid="ue-delete-selected"
            >
              <Trash2 width={13} height={13} />
              Delete selected
            </button>
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={() => setSelected(new Set())}
            >
              Clear selection
            </button>
          </div>
        )}
      </section>

      <div className="ep-card overflow-x-auto">
        <table className="ep-table" data-testid="ue-table">
          <thead>
            <tr>
              <th className="w-8">
                <input
                  type="checkbox"
                  aria-label="Select all on page"
                  checked={rows.length > 0 && rows.every((row) => selected.has(row.profile.id))}
                  onChange={(event) => {
                    setSelected((prev) => {
                      const next = new Set(prev);
                      if (event.target.checked) {
                        for (const row of rows) next.add(row.profile.id);
                      } else {
                        for (const row of rows) next.delete(row.profile.id);
                      }
                      return next;
                    });
                  }}
                  data-testid="ue-select-all"
                />
              </th>
              <th>UE ID / Profile</th>
              <th>Owner</th>
              <th>Serving gNB</th>
              <th>Registration</th>
              <th>PDU Session</th>
              <th>RRC</th>
              <th>UE IP</th>
              <th>Traffic</th>
              <th>Assigned Scenario</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const assignment = assignmentByUe.get(row.profile.id);
              const scenario = assignment ? scenarioById.get(assignment.scenarioId) : undefined;
              const profile = scenario ? certifiedProfileFor(scenario) : null;
              const isShared = row.backend ? !row.backend.controller_owned : false;
              const backendId = row.backend?.internal_ue_id ?? row.backend?.id;
              const isActiveForUe =
                activeJob?.target_ue_id != null && activeJob.target_ue_id === backendId;
              const notProvisioned = !row.backend;

              return (
                <tr
                  key={row.profile.id}
                  data-testid={`ue-row-${row.profile.id}`}
                  data-selected={selected.has(row.profile.id) ? 'true' : undefined}
                >
                  <td>
                    <input
                      type="checkbox"
                      aria-label={`Select ${row.profile.id}`}
                      checked={selected.has(row.profile.id)}
                      onChange={(event) => {
                        setSelected((prev) => {
                          const next = new Set(prev);
                          if (event.target.checked) next.add(row.profile.id);
                          else next.delete(row.profile.id);
                          return next;
                        });
                      }}
                      data-testid={`ue-select-${row.profile.id}`}
                    />
                  </td>
                  <td>
                    <div className="flex flex-col">
                      {polarisProvisioning ? (
                        <Link
                          to={`/ues/${encodeURIComponent(row.profile.id)}`}
                          className="font-medium mono text-primary hover:underline"
                          data-testid={`ue-detail-link-${row.profile.id}`}
                        >
                          {row.profile.id}
                        </Link>
                      ) : (
                        <span className="font-medium mono">{row.profile.id}</span>
                      )}
                      {row.backend?.internal_ue_id && (
                        <span className="text-text-secondary text-ep-xs mono truncate">
                          {row.backend.internal_ue_id}
                        </span>
                      )}
                      {notProvisioned && !profileBackend && (
                        <span className="text-ep-xs text-text-secondary">
                          Not provisioned on backend
                        </span>
                      )}
                      {profileBackend && row.profile.subscriptionStatus && (
                        <span
                          className={`text-ep-xs ${
                            row.profile.subscriptionStatus === 'VERIFIED' ? 'text-success' : 'text-warning'
                          }`}
                          data-testid={`ue-subscription-${row.profile.id}`}
                        >
                          {row.profile.subscriptionStatus === 'VERIFIED'
                            ? 'Open5GS subscription verified'
                            : 'Not provisioned in Open5GS'}
                        </span>
                      )}
                      {isShared && (
                        <span className="text-ep-xs text-warning flex items-center gap-1">
                          <AlertTriangle width={10} height={10} />
                          Shared — protected
                        </span>
                      )}
                    </div>
                  </td>
                  <td>{row.profile.owner}</td>
                  <td className="mono">{row.profile.servingGnb}</td>
                  <td>
                    <StatusIndicator
                      state={row.backend?.registration_state ?? 'UNKNOWN'}
                      compact
                    />
                  </td>
                  <td>
                    <StatusIndicator state={row.backend?.pdu_session ?? 'UNKNOWN'} compact />
                  </td>
                  <td>
                    <StatusIndicator state={row.backend?.rrc_state ?? 'UNKNOWN'} compact />
                  </td>
                  <td className="mono text-ep-xs">
                    {row.backend?.ue_ip ?? row.profile.ueIp ?? '—'}
                  </td>
                  <td>{row.backend?.traffic_state ?? '—'}</td>
                  <td>
                    <div className="flex flex-col gap-1">
                      <select
                        className="ep-input text-ep-sm py-1 h-8"
                        value={assignment?.scenarioId ?? ''}
                        onChange={(event) => {
                          if (profileBackend) {
                            void setBackendAssignment(
                              [row.profile.id],
                              event.target.value === '' ? null : event.target.value,
                              assignment?.autoRun ?? false,
                            );
                          } else if (event.target.value === '') {
                            assignments.clear(row.profile.id);
                          } else {
                            assignments.assign(
                              row.profile.id,
                              event.target.value,
                              assignment?.autoRun ?? false,
                            );
                          }
                        }}
                        disabled={!canOperate || isShared}
                        data-testid={`assign-select-${row.profile.id}`}
                      >
                        <option value="">— None —</option>
                        {library.scenarios.map((item) => (
                          <option key={item.id} value={item.id}>
                            {item.name} (v{item.version})
                          </option>
                        ))}
                      </select>
                      {scenario && !profile && (
                        <span className="text-ep-xs text-warning flex items-center gap-1">
                          <AlertTriangle width={10} height={10} />
                          Backend support required.
                        </span>
                      )}
                    </div>
                  </td>
                  <td>
                    <div className="flex items-center gap-1 flex-nowrap">
                      <button
                        type="button"
                        className="ep-button ep-button-sm"
                        aria-label={`Edit ${row.profile.id}`}
                        onClick={() =>
                          setFormState({ mode: 'edit', initial: toDraft(row.profile) })
                        }
                        data-testid={`ue-edit-${row.profile.id}`}
                      >
                        <Edit width={13} height={13} />
                      </button>
                      <button
                        type="button"
                        className="ep-button ep-button-sm"
                        aria-label={`Clone ${row.profile.id}`}
                        onClick={() => {
                          const next = { ...toDraft(row.profile), id: `${row.profile.id}-copy` };
                          setFormState({ mode: 'clone', initial: next });
                        }}
                        data-testid={`ue-clone-${row.profile.id}`}
                      >
                        <Copy width={13} height={13} />
                      </button>
                      <button
                        type="button"
                        className="ep-button ep-button-sm ep-button-danger"
                        aria-label={`Delete ${row.profile.id}`}
                        onClick={() => setConfirmDelete([row.profile.id])}
                        disabled={!canOperate}
                        data-testid={`ue-delete-${row.profile.id}`}
                      >
                        <Trash2 width={13} height={13} />
                      </button>
                      <button
                        type="button"
                        className="ep-button ep-button-sm"
                        aria-label={`Start ${row.profile.id}`}
                        onClick={() => void startBackendUe(row)}
                        disabled={
                          !canOperate ||
                          isShared ||
                          notProvisioned ||
                          !row.backend?.actions?.start ||
                          startUe.isPending
                        }
                        title={
                          notProvisioned
                            ? 'Not provisioned on backend'
                            : row.backend?.actions?.reason || undefined
                        }
                        data-testid={`ue-start-${row.profile.id}`}
                      >
                        Start
                      </button>
                      <button
                        type="button"
                        className="ep-button ep-button-sm"
                        aria-label={`Run scenario on ${row.profile.id}`}
                        onClick={() => scenario && setConfirmRun({ row, scenario })}
                        disabled={
                          !canOperate ||
                          isShared ||
                          notProvisioned ||
                          !scenario ||
                          !profile
                        }
                        title={
                          notProvisioned
                            ? 'Not provisioned on backend'
                            : !scenario
                              ? 'No scenario assigned'
                              : !profile
                                ? 'Backend support required'
                                : undefined
                        }
                        data-testid={`ue-run-${row.profile.id}`}
                      >
                        Run
                      </button>
                      <button
                        type="button"
                        className="ep-button ep-button-sm ep-button-danger"
                        aria-label={`Stop scenario on ${row.profile.id}`}
                        onClick={() => setConfirmStop(row)}
                        disabled={
                          !canOperate ||
                          isShared ||
                          notProvisioned ||
                          !isActiveForUe ||
                          stopScenario.isPending
                        }
                        title={
                          isShared
                            ? 'Shared UE — protected'
                            : notProvisioned
                              ? 'Not provisioned on backend'
                              : !isActiveForUe
                                ? 'No active job owned by this UE'
                                : undefined
                        }
                        data-testid={`ue-stop-${row.profile.id}`}
                      >
                        <StopCircle width={13} height={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={11} className="text-center text-text-secondary py-6">
                  {profiles.length === 0
                    ? 'No UE profile yet. Add one, bulk-create or import CSV.'
                    : 'No profile matches the current filter.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <nav
        className="flex items-center justify-between gap-2 mt-3 text-ep-sm text-text-secondary"
        data-testid="ue-pagination"
      >
        <div>
          Showing <span className="mono">{paged.filteredTotal > 0 ? pageStart : 0}</span>–
          <span className="mono">{paged.filteredTotal > 0 ? pageEnd : 0}</span> of{' '}
          <span className="mono">{paged.filteredTotal.toLocaleString()}</span>
          {paged.filteredTotal !== paged.total && (
            <>
              {' '}
              (filtered from <span className="mono">{paged.total.toLocaleString()}</span>)
            </>
          )}
        </div>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1">
            Rows
            <select
              className="ep-input py-1 h-8"
              value={pageSize}
              onChange={(event) => {
                setPageSize(Number(event.target.value));
                setPage(1);
              }}
              data-testid="ue-page-size"
            >
              {PAGE_SIZES.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={() => setPage((prev) => Math.max(1, prev - 1))}
            disabled={paged.page <= 1}
            aria-label="Previous page"
            data-testid="ue-page-prev"
          >
            <ChevronLeft width={13} height={13} />
          </button>
          <span className="mono">
            {paged.page} / {paged.pageCount}
          </span>
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={() => setPage((prev) => Math.min(paged.pageCount, prev + 1))}
            disabled={paged.page >= paged.pageCount}
            aria-label="Next page"
            data-testid="ue-page-next"
          >
            <ChevronRight width={13} height={13} />
          </button>
        </div>
      </nav>

      {feedback && (
        <p
          className="ep-badge mt-3 text-ep-sm border-primary/40"
          data-testid="ue-feedback"
          role="status"
          aria-live="polite"
        >
          {feedback}
        </p>
      )}

      {/* Dialogs */}
      <CsvImportDialog
        open={polarisProvisioning && backendCsvOpen}
        onClose={() => setBackendCsvOpen(false)}
        target="ue-profiles"
        title="Import UE profiles (CSV)"
        description="POST /ue-profiles/bulk (text/csv). Expected header: ue_id,gnb_id,note,imsi. Capped at 100 000 rows per request."
        onImported={(report) =>
          setFeedback(`CSV import done · ${report.accepted} accepted · ${report.rejected} rejected.`)
        }
      />

      <UeProvisioningAddDialog
        open={polarisProvisioning && provisioningAddOpen}
        onClose={() => {
          setProvisioningAddOpen(false);
          setProvisioningAddError(null);
        }}
        onSubmit={submitProvisioningAdd}
        gnbs={(gnbList.data?.items ?? []) as WireGnb[]}
        owners={ownerList.data?.items ?? []}
        gnbsLoading={gnbList.isLoading}
        ownersLoading={ownerList.isLoading}
        gnbsError={
          gnbList.isError ? `GNBs backend pending · ${(gnbList.error as Error).message}` : null
        }
        ownersError={
          ownerList.isError
            ? `Owners backend pending · ${(ownerList.error as Error).message}`
            : null
        }
        submitting={provisioningAddSubmitting}
        submitError={provisioningAddError}
      />

      <UeProfileBackendFormDialog
        mode={formState?.mode ?? 'create'}
        open={profileBackend && formState != null}
        initial={formState?.initial ? backendProfiles.wireById.get(formState.initial.id) ?? null : null}
        template={backendProfiles.wireById.values().next().value ?? null}
        gnbs={backendProfiles.gnbs}
        slots={backendProfiles.slots}
        slotsError={backendProfiles.slotsError}
        onCancel={() => setFormState(null)}
        onSubmit={submitBackend}
      />

      {/* 0.6.0 — the local-draft form stays mounted only when polarisProvisioning
          is OFF. The LOT requires it to disappear entirely in the new UX; profileBackend
          then becomes the only path. */}
      {!polarisProvisioning && (
        <UeProfileFormDialog
          mode={formState?.mode ?? 'create'}
          initial={formState?.initial}
          open={!profileBackend && formState != null}
          onCancel={() => setFormState(null)}
          onSubmit={async (draft) => {
            if (!formState) return;
            if (formState.mode === 'create') await submitCreate(draft);
            else if (formState.mode === 'edit') await submitEdit(draft);
            else await submitClone(draft);
          }}
        />
      )}

      <UeBulkCreateDialog
        open={bulkOpen}
        existingCount={profiles.length}
        onCancel={() => setBulkOpen(false)}
        onSubmit={handleBulk}
      />

      <AssignScenarioDialog
        open={assignOpen}
        selectedCount={selected.size}
        scenarios={library.scenarios}
        onCancel={() => setAssignOpen(false)}
        onSubmit={handleAssign}
      />

      <ConfirmDialog
        open={confirmDelete != null}
        title={confirmDelete && confirmDelete.length === 1 ? 'Delete UE profile' : 'Delete UE profiles'}
        description={
          confirmDelete == null
            ? ''
            : confirmDelete.length === 1
              ? `Remove profile "${confirmDelete[0]}" and clear any scenario assignment pointing at it. The backend will keep any live UE until stopped from there.`
              : `Remove ${confirmDelete.length} selected profiles and clear scenario assignments. The backend will keep any live UEs until stopped from there.`
        }
        confirmLabel="Delete"
        tone="danger"
        onCancel={() => setConfirmDelete(null)}
        onConfirm={() => void removeSelected()}
      />

      <ConfirmDialog
        open={confirmRun != null}
        title="Run scenario"
        description={
          confirmRun
            ? `Dispatch ${confirmRun.scenario.name} (v${confirmRun.scenario.version}) to ${confirmRun.row.profile.id} via the certified backend profile. Loop and random values execute server-side.`
            : ''
        }
        confirmLabel="Confirm run"
        onCancel={() => setConfirmRun(null)}
        onConfirm={() => {
          if (confirmRun) void runScenarioOn(confirmRun.row, confirmRun.scenario);
          setConfirmRun(null);
        }}
        busy={startScenario.isPending}
      />

      <ConfirmDialog
        open={confirmStop != null}
        title="Stop scenario"
        description={
          confirmStop
            ? `Send a stop for the active controller-owned job targeting ${confirmStop.profile.id}. The UE and its PDU session stay running unless the scenario explicitly includes a stop and the backend authorizes it.`
            : ''
        }
        confirmLabel="Confirm stop"
        tone="danger"
        onCancel={() => setConfirmStop(null)}
        onConfirm={() => {
          if (confirmStop) void stopFor(confirmStop);
          setConfirmStop(null);
        }}
        busy={stopScenario.isPending}
      />

    </>
  );
}

function toDraft(record: UeProfileRecord): UeProfileDraft {
  return {
    id: record.id,
    owner: record.owner,
    servingGnb: record.servingGnb,
    imsi: record.imsi ?? '',
    plmn: record.plmn ?? '',
    apn: record.apn ?? '',
    ueIp: record.ueIp ?? '',
    notes: record.notes ?? '',
  };
}

function uniqueSorted(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim() !== ''))).sort((a, b) =>
    a.localeCompare(b),
  );
}

function timestampSuffix(): string {
  const d = new Date();
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}`;
}

function pad(n: number): string {
  return n.toString().padStart(2, '0');
}
