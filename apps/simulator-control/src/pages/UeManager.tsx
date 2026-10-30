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
import { RowActionMenu } from '@/ui/RowActionMenu';
import { formatImsiForRole } from '@/ue/imsiHelpers';
import { LiveGrantDialog } from '@/ue/LiveGrantDialog';
import { LiveGrantCountdown } from '@/ue/LiveGrantCountdown';
import { Shield } from 'lucide-react';
import {
  useAuth,
  useDnns,
  useGenerateSubscribers,
  usePlmns,
  useScenarioRuntime,
  useStartScenario,
  useStartUe,
  useStopScenario,
  useStopUe,
  useSubscriberSlots,
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

/** Compute the next-free `UE-NN` id by scanning existing ids and picking
 * the lowest unused slot (#29f). Padding matches the UE_ID regex
 * (`UE-NN` for < 100, `UE-NNNNN` beyond) so the prefilled value is always
 * a valid identifier. */
export function nextFreeUeIdFrom(existing: string[]): string {
  const used = new Set<number>();
  for (const id of existing) {
    const match = /^UE-(\d{2,})$/i.exec(id.trim());
    if (match) used.add(Number(match[1]));
  }
  let candidate = 1;
  while (used.has(candidate)) candidate += 1;
  const padded =
    candidate < 100
      ? candidate.toString().padStart(2, '0')
      : candidate.toString().padStart(5, '0');
  return `UE-${padded}`;
}

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
  const plmnList = usePlmns();
  const dnnList = useDnns();
  const subscriberSlots = useSubscriberSlots();
  const generateSubscriber = useGenerateSubscribers();
  const [generateError, setGenerateError] = useState<string | null>(null);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [assignOpen, setAssignOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string[] | null>(null);
  const [confirmStop, setConfirmStop] = useState<MergedRow | null>(null);
  const [confirmRun, setConfirmRun] = useState<{ row: MergedRow; scenario: Scenario } | null>(null);
  // 0.11.1 (#46) — Live-grant dialog state. `prefillUeIds` lets the
  // 423 feedback banner open the dialog with the exact UE whose Run
  // was refused.
  const [grantDialog, setGrantDialog] = useState<{
    open: boolean;
    prefillUeIds?: string[];
  }>({ open: false });
  // 0.11.1 (#46) — When the last Run returned 423, remember which UE
  // id triggered it so the feedback banner can offer an inline
  // "Autoriser le live" shortcut that prefills the dialog.
  const [feedbackGrantHint, setFeedbackGrantHint] = useState<string | null>(null);

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
        includeImsi: canOperate,
      }),
    [profiles, search, ownerFilter, gnbFilter, page, pageSize, canOperate],
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

  // 0.9.4 — polarisProvisioning Add UE flow (#29). The dialog binds the
  // UE profile to a provisioned subscriber slot (`provisioning_slot` =
  // SUB-…) and surfaces PLMN / DNN / SST / SD as lab-served dropdowns.
  // The IMSI text input is gone: identity material stays server-side.
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
        const status = (error as { status?: number }).status;
        const code = (error as { code?: string }).code;
        const message = (error as Error).message;
        // 0.10.2 (#43) — Translate the backend codes operators actually
        // see into plain-language guidance. We keep the technical code
        // trailing, once, small, so engineers still have the exact token
        // to file a ticket on.
        setFeedback(humanRunError(status, code, message));
        // 0.11.1 (#46) — If the backend refused with 423
        // LIVE_EXECUTION_NOT_AUTHORIZED, surface a one-click
        // shortcut to the Grant dialog with the UE prefilled.
        if (status === 423 && code === 'SCENARIO_DEFINITION_LIVE_EXECUTION_NOT_AUTHORIZED') {
          setFeedbackGrantHint(row.profile.id);
        } else {
          setFeedbackGrantHint(null);
        }
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
    // 0.10.0 — Stop prefers the active scenario job (if the UE owns it), and
    // falls back to the direct backend Stop action otherwise. Previously the
    // button was disabled whenever no active_job existed; now the toggle
    // follows backend.actions.stop so running UEs can be stopped directly.
    const backendId = row.backend?.internal_ue_id ?? row.backend?.id;
    if (activeJob?.job_id && (!activeJob.target_ue_id || activeJob.target_ue_id === backendId)) {
      try {
        await stopScenario.mutateAsync(activeJob.job_id);
        setFeedback(`Stop sent for job ${activeJob.job_id}.`);
      } catch (error) {
        setFeedback((error as Error).message);
      }
      return;
    }
    if (row.backend?.actions?.stop) {
      await stopBackendUe(row);
      return;
    }
    setFeedback('No active job and backend reports Stop not available.');
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
        description="Operator-authored UE profiles reconciled with the POLARIS backend inventory. Backend state (registration, PDU, UE IP, traffic) is read live from POLARIS."
        actions={
          <div className="flex items-center gap-2 flex-wrap justify-end">
            <LiveGrantCountdown canRevoke={canOperate} />
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={() => setGrantDialog({ open: true })}
              disabled={!canOperate}
              title={
                canOperate
                  ? 'Ouvrir une fenêtre Live bornée (15 / 30 / 60 min)'
                  : 'Rôle viewer : lecture seule.'
              }
              data-testid="live-grant-open"
            >
              <Shield width={13} height={13} aria-hidden="true" />
              <span className="ml-1">Autoriser le live</span>
            </button>
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
              placeholder={
                canOperate
                  ? 'Search id, owner, gNB, IMSI, UE IP…'
                  : 'Search id, owner, gNB, UE IP…'
              }
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
            title={
              !canOperate
                ? 'Rôle viewer : création non autorisée.'
                : profileBackend
                  ? 'Bulk create via /ue-profiles/bulk — client UI planned for V1.1 (10/100/1000/10000).'
                  : undefined
            }
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

      <div className="ep-card">
        <table
          className="ep-table w-full table-fixed"
          data-testid="ue-table"
        >
          <colgroup>
            {/* 0.10.4 — Runtime columns collapsed into a single "État" cell.
                The pre-0.10.4 5-column Runtime block still crammed labels
                into tight widths at 1280px; the chip layout fits the
                compact label + IP under a single 18 % column. RRC and
                traffic moved to the Activity page. Total = 100 %. */}
            <col style={{ width: '2rem' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '18%' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '9%' }} />
            <col className="runtime-col" style={{ width: '18%' }} />
            <col style={{ width: '15%' }} />
            <col style={{ width: '20%' }} />
          </colgroup>
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
              <th>UE ID</th>
              <th>IMSI</th>
              <th>Owner</th>
              <th>Serving gNB</th>
              <th>État</th>
              <th>Scenario</th>
              <th className="text-right">Actions</th>
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
              // 0.10.4 — Idle (= "Not running" chip) now follows the
              // backend's `process_state` signal, not just the registration /
              // PDU / RRC trio. A UE whose process is `idle` is stopped even
              // when it still carries a `DEREGISTERED` registration remnant.
              const processState = (row.backend?.process_state ?? '').toLowerCase();
              const runtimeStates = [
                row.backend?.registration_state,
                row.backend?.pdu_session,
              ].map((state) => (state ?? '').toUpperCase());
              const isRuntimeIdle =
                !row.backend ||
                processState === 'idle' ||
                processState === 'stopped' ||
                processState === 'exited' ||
                runtimeStates.every(
                  (state) => state === '' || state === 'UNKNOWN' || state === 'INACTIVE',
                );
              // 0.10.2 (#42f) — Honest owner: the backend currently stores
              // the UE's display name in the `name` field; it is NOT the
              // operator identity. If it equals the UE id (common default),
              // show the em dash instead of pretending the UE owns itself.
              const ownerCandidate = row.profile.owner?.trim();
              const displayOwner =
                ownerCandidate && ownerCandidate !== row.profile.id ? ownerCandidate : '—';
              // 0.10.0 — Start / Stop is a state-driven toggle: the backend's
              // own `actions` map tells us which transition is applicable
              // right now. A running UE advertises `stop:true`; an idle one
              // advertises `start:true`. The active-job path reinforces Stop
              // when a controller-owned job is actually targeting this UE.
              const backendCanStop = row.backend?.actions?.stop === true;
              const backendCanStart = row.backend?.actions?.start === true;
              const showStop = backendCanStop || isActiveForUe;
              // 0.10.0 — explicit disable reasons so operators see WHY a button
              // is grayed instead of guessing (viewer, 423-live-closed, UE active,
              // shared, …). Returned string becomes the native tooltip.
              const liveClosed = row.backend?.actions?.reason?.includes('423') ||
                /LIVE_EXECUTION_NOT_AUTHORIZED/.test(row.backend?.actions?.reason ?? '');
              const startDisabled =
                !canOperate ||
                isShared ||
                notProvisioned ||
                !backendCanStart ||
                startUe.isPending;
              const startReason = !canOperate
                ? 'Rôle viewer : lecture seule.'
                : isShared
                  ? 'UE partagée — protégée.'
                  : notProvisioned
                    ? 'Pas provisionné côté backend.'
                    : isActiveForUe
                      ? 'UE déjà active.'
                      : liveClosed
                        ? 'Live fermé (HTTP 423) — approbation requise.'
                        : !row.backend?.actions?.start
                          ? row.backend?.actions?.reason || 'Start indisponible.'
                          : null;
              const stopDisabled =
                !canOperate ||
                isShared ||
                notProvisioned ||
                !(isActiveForUe || backendCanStop) ||
                stopScenario.isPending;
              const stopReason = !canOperate
                ? 'Rôle viewer : lecture seule.'
                : isShared
                  ? 'UE partagée — protégée.'
                  : notProvisioned
                    ? 'Pas provisionné côté backend.'
                    : !(isActiveForUe || backendCanStop)
                      ? 'Aucune action Stop disponible côté backend.'
                      : null;
              const runDisabled =
                !canOperate ||
                isShared ||
                notProvisioned ||
                !scenario ||
                (!scenarioBackend && !profile);
              const runReason = !canOperate
                ? 'Rôle viewer : lecture seule.'
                : isShared
                  ? 'UE partagée — protégée.'
                  : notProvisioned
                    ? 'Pas provisionné côté backend.'
                    : !scenario
                      ? 'Aucun scénario assigné.'
                      : !scenarioBackend && !profile
                        ? 'Scénario non couvert par le profil certifié legacy.'
                        : liveClosed
                          ? 'Live fermé (HTTP 423) — approbation requise.'
                          : null;
              const editDisabled = !canOperate;
              const editReason = !canOperate ? 'Rôle viewer : lecture seule.' : null;
              const deleteReason = !canOperate ? 'Rôle viewer : lecture seule.' : null;

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
                      {/* 0.11.0 (#37) — The UE id click now lands on the
                          per-UE Activity page (the detail page stays
                          reachable via the "UE detail" button inside
                          Activity). The link is role-independent — Activity
                          is read-only, open to every signed-in viewer. */}
                      <Link
                        to={`/ues/${encodeURIComponent(row.profile.id)}/activity`}
                        className="font-medium mono text-primary hover:underline"
                        data-testid={`ue-detail-link-${row.profile.id}`}
                      >
                        {row.profile.id}
                      </Link>
                      {row.backend?.internal_ue_id &&
                        row.backend.internal_ue_id !== row.profile.id && (
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
                  {/* 0.10.2 (#41) — IMSI column. Operators see the raw IMSI;
                      viewers see the solid mask only. */}
                  <td
                    className="mono text-ep-xs"
                    data-testid={`ue-imsi-${row.profile.id}`}
                  >
                    {formatImsiForRole(row.profile.imsi, canOperate)}
                  </td>
                  <td data-testid={`ue-owner-${row.profile.id}`}>{displayOwner}</td>
                  <td className="mono">{row.profile.servingGnb || '—'}</td>
                  {/* 0.10.4 — Single "État" cell replacing the 5-column
                      Runtime block. The chip shows at most two state hints
                      (`Registered · PDU active`), falls back to `Not running`
                      when the UE is idle, and carries the UE IP on a second
                      line below. RRC and traffic breakdown live on the
                      Activity page now. */}
                  <td
                    className="px-2"
                    data-testid={`ue-etat-${row.profile.id}`}
                  >
                    <div className="flex flex-col gap-0.5">
                      <StatusIndicator
                        state={etatToneState(row.backend, isRuntimeIdle)}
                        label={etatLabel(row.backend, isRuntimeIdle)}
                        compact
                      />
                      {(row.backend?.ue_ip ?? row.profile.ueIp) && (
                        <span className="mono text-ep-xs text-text-secondary">
                          {row.backend?.ue_ip ?? row.profile.ueIp}
                        </span>
                      )}
                    </div>
                  </td>
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
                      {/* 0.10.0 — "Backend support required" is only honest for the legacy
                          certified-profile runner (bounded-controller-ue-udp-v1). When
                          scenarioBackend is on, /scenario-runs covers traffic_ul / traffic_dl /
                          transfer_verify / detach, so we must not block the row for them. */}
                      {!scenarioBackend && scenario && !profile && (
                        <span className="text-ep-xs text-warning flex items-center gap-1">
                          <AlertTriangle width={10} height={10} />
                          Backend support required.
                        </span>
                      )}
                    </div>
                  </td>
                  <td>
                    <div className="flex items-center justify-end gap-1 flex-nowrap">
                      {/* 0.10.0 — Start/Stop are state-driven: whichever action
                          applies to the UE's current runtime is shown; the other is
                          collapsed. Keeps the row within the 10% column at 1440/1920. */}
                      {showStop ? (
                        <button
                          type="button"
                          className="ep-button ep-button-sm ep-button-danger"
                          onClick={() => setConfirmStop(row)}
                          disabled={stopDisabled}
                          title={stopReason ?? 'Arrêter le job actif de cette UE.'}
                          data-testid={`ue-stop-${row.profile.id}`}
                        >
                          <StopCircle width={13} height={13} aria-hidden="true" />
                          <span className="ml-1">Stop</span>
                        </button>
                      ) : (
                        <button
                          type="button"
                          className="ep-button ep-button-sm"
                          onClick={() => void startBackendUe(row)}
                          disabled={startDisabled}
                          title={startReason ?? 'Démarrer cette UE sur le backend.'}
                          data-testid={`ue-start-${row.profile.id}`}
                        >
                          Start
                        </button>
                      )}
                      <button
                        type="button"
                        className="ep-button ep-button-sm"
                        onClick={() => scenario && setConfirmRun({ row, scenario })}
                        disabled={runDisabled}
                        title={runReason ?? 'Dispatcher le scénario assigné sur cette UE.'}
                        data-testid={`ue-run-${row.profile.id}`}
                      >
                        Run
                      </button>
                      <RowActionMenu
                        ariaLabel={`More actions for ${row.profile.id}`}
                        testid={`ue-more-${row.profile.id}`}
                        items={[
                          {
                            key: 'edit',
                            label: 'Edit',
                            icon: <Edit width={12} height={12} aria-hidden="true" />,
                            onSelect: () =>
                              setFormState({ mode: 'edit', initial: toDraft(row.profile) }),
                            disabled: editDisabled,
                            disabledReason: editReason ?? undefined,
                            testid: `ue-edit-${row.profile.id}`,
                          },
                          {
                            key: 'clone',
                            label: 'Clone',
                            icon: <Copy width={12} height={12} aria-hidden="true" />,
                            onSelect: () => {
                              const next = {
                                ...toDraft(row.profile),
                                id: `${row.profile.id}-copy`,
                              };
                              setFormState({ mode: 'clone', initial: next });
                            },
                            testid: `ue-clone-${row.profile.id}`,
                          },
                          {
                            key: 'delete',
                            label: 'Delete',
                            icon: <Trash2 width={12} height={12} aria-hidden="true" />,
                            tone: 'danger',
                            onSelect: () => setConfirmDelete([row.profile.id]),
                            disabled: !canOperate,
                            disabledReason: deleteReason ?? undefined,
                            testid: `ue-delete-${row.profile.id}`,
                          },
                        ]}
                      />
                    </div>
                  </td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={8} className="text-center text-text-secondary py-6">
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
        <div
          className="mt-3 flex flex-wrap items-center gap-2"
          data-testid="ue-feedback-row"
        >
          <p
            className="ep-badge text-ep-sm border-primary/40"
            data-testid="ue-feedback"
            role="status"
            aria-live="polite"
          >
            {feedback}
          </p>
          {/* 0.11.1 (#46) — When a Run returned 423, offer a one-click
              shortcut to the "Autoriser le live" dialog with the UE
              prefilled. Visible only to operators. */}
          {feedbackGrantHint && canOperate && (
            <button
              type="button"
              className="ep-button ep-button-sm ep-button-primary"
              onClick={() =>
                setGrantDialog({ open: true, prefillUeIds: [feedbackGrantHint] })
              }
              data-testid="ue-feedback-open-grant"
            >
              <Shield width={13} height={13} aria-hidden="true" />
              <span className="ml-1">Autoriser le live pour {feedbackGrantHint}</span>
            </button>
          )}
        </div>
      )}

      {/* 0.11.1 (#46) — Live-grant dialog, driven from the header
          button and from the 423 Run-feedback shortcut. */}
      <LiveGrantDialog
        open={grantDialog.open}
        availableUeIds={profiles.map((profile) => profile.id)}
        defaultSelectedUeIds={grantDialog.prefillUeIds}
        onClose={() => setGrantDialog({ open: false })}
        onCreated={(id) => {
          setFeedback(`Live grant ${id} ouvert.`);
          setFeedbackGrantHint(null);
        }}
      />

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
          setGenerateError(null);
        }}
        onSubmit={submitProvisioningAdd}
        onGenerateSubscriber={async () => {
          setGenerateError(null);
          try {
            // 0.10.0 — Default AMBR to 1 Gbit/s (1_000_000 kbps on each
            // direction) so the Generate path matches the manual Add
            // Subscriber flow. Operators were having to re-provision when
            // the server-side default (1 Mbit/s legacy) was too tight.
            const result = await generateSubscriber.mutateAsync({
              count: 1,
              sst: 1,
              sd: '010203',
              dnns: ['internet'],
              ambr: { uplink: 1_000_000, downlink: 1_000_000 },
            });
            const slot = result.slots[0]?.slot ?? null;
            if (slot) await subscriberSlots.refetch();
            return slot;
          } catch (error) {
            const status = error instanceof ApiError ? error.status : null;
            const code = error instanceof ApiError ? error.code : 'SUBSCRIBER_GENERATE_FAILED';
            setGenerateError(
              `${status ? `HTTP ${status} · ` : ''}${code} · ${(error as Error).message}`,
            );
            return null;
          }
        }}
        gnbs={(gnbList.data?.items ?? []) as WireGnb[]}
        owners={ownerList.data?.items ?? []}
        plmns={plmnList.data?.items ?? []}
        dnns={dnnList.data?.items ?? []}
        subscribers={subscriberSlots.data ?? []}
        nextFreeUeId={nextFreeUeIdFrom(profiles.map((item) => item.id))}
        gnbsLoading={gnbList.isLoading}
        ownersLoading={ownerList.isLoading}
        plmnsLoading={plmnList.isLoading}
        dnnsLoading={dnnList.isLoading}
        subscribersLoading={subscriberSlots.isLoading}
        gnbsError={
          gnbList.isError ? `GNBs backend pending · ${(gnbList.error as Error).message}` : null
        }
        ownersError={
          ownerList.isError
            ? `Owners backend pending · ${(ownerList.error as Error).message}`
            : null
        }
        plmnsError={
          plmnList.isError ? `PLMNs backend pending · ${(plmnList.error as Error).message}` : null
        }
        dnnsError={
          dnnList.isError ? `DNNs backend pending · ${(dnnList.error as Error).message}` : null
        }
        subscribersError={
          subscriberSlots.isError
            ? `Subscribers backend pending · ${(subscriberSlots.error as Error).message}`
            : null
        }
        submitting={provisioningAddSubmitting}
        submitError={provisioningAddError}
        generating={generateSubscriber.isPending}
        generateError={generateError}
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

/**
 * 0.10.4 — Compact label for the single "État" cell. We render AT MOST
 * two chips concatenated with a middle dot (`Registered · PDU active`)
 * so the content fits inside a 18 % column at 1280 px. When the UE is
 * idle (no backend record or every runtime state blank/UNKNOWN) we
 * surface the honest `Not running` instead.
 *
 * Visible only exported for the unit tests that pin the wording.
 */
export function etatLabel(backend: UeState | undefined, idle: boolean): string {
  if (idle || !backend) return 'Not running';
  const parts: string[] = [];
  const reg = (backend.registration_state ?? '').toUpperCase();
  const pdu = (backend.pdu_session ?? '').toUpperCase();
  if (reg === 'REGISTERED') parts.push('Registered');
  else if (reg === 'DEREGISTERED') parts.push('Deregistered');
  else if (reg && reg !== 'UNKNOWN' && reg !== 'INACTIVE') {
    parts.push(humaniseState(reg));
  }
  if (pdu === 'ACTIVE') parts.push('PDU active');
  else if (pdu && pdu !== 'UNKNOWN' && pdu !== 'INACTIVE' && pdu !== 'IDLE') {
    parts.push(humaniseState(pdu));
  }
  return parts.length === 0 ? 'Not running' : parts.join(' · ');
}

/**
 * 0.10.4 — Tone marker for the État chip. Fed to StatusIndicator's
 * `state` prop so the existing tone-map (`REGISTERED` → success, etc.)
 * paints the dot without us re-deriving the colour here.
 */
export function etatToneState(backend: UeState | undefined, idle: boolean): string {
  if (idle || !backend) return 'UNKNOWN';
  const reg = (backend.registration_state ?? '').toUpperCase();
  if (reg === 'REGISTERED') return 'REGISTERED';
  if (reg === 'DEREGISTERED') return 'OFFLINE';
  return reg || 'UNKNOWN';
}

function humaniseState(upper: string): string {
  const lower = upper.toLowerCase();
  return lower.charAt(0).toUpperCase() + lower.slice(1);
}

/**
 * 0.10.2 (#43) — Map the POLARIS Run error vocabulary onto French
 * sentences the operator can act on. The returned string always carries
 * the technical code once, trailing and small, so a reader can still
 * paste the exact token into an incident ticket. Covers the cases the
 * backend actually produces at Run time: HTTP 423 live refusals, HTTP
 * 422 missing-receiver guards, HTTP 401 authentication, and the
 * open-ended fallback.
 */
export function humanRunError(
  status: number | undefined,
  code: string | null | undefined,
  message: string | null | undefined,
): string {
  const trailing = code ?? (status != null ? `HTTP ${status}` : 'ERROR');
  const headline = (() => {
    if (status === 401 || code === 'AUTHENTICATION_REQUIRED') {
      return 'Session expirée — reconnectez-vous pour relancer le scénario.';
    }
    if (status === 423) {
      if (code === 'SCENARIO_DEFINITION_LIVE_EXECUTION_NOT_AUTHORIZED') {
        return 'Exécution live non autorisée : demandez l’ouverture du live.';
      }
      if (code === 'LIVE_UE_EXISTING_CONTAINER_ENVELOPE_MISMATCH') {
        return "Un conteneur de même nom existe déjà avec une configuration différente — supprimez-le ou éditez le profil.";
      }
      return 'Exécution live non autorisée : demandez l’ouverture du live.';
    }
    if (status === 422) {
      if (code === 'DL_SENDER_NOT_AVAILABLE') {
        return "Trafic descendant indisponible : le sender DN n’est pas prêt.";
      }
      if (code === 'UL_RECEIVER_NOT_AVAILABLE') {
        return "Trafic montant indisponible : le receiver UL n’est pas prêt.";
      }
      if (code === 'TRANSFER_PEER_NOT_AVAILABLE') {
        return "Vérification de transfert indisponible : le peer n’est pas prêt.";
      }
      if (code === 'IMS_NOT_AVAILABLE') {
        return "IMS indisponible : voice-call / IMS register non exécutable.";
      }
    }
    return message?.trim() || 'Démarrage du scénario refusé.';
  })();
  return `${headline} · ${trailing}`;
}
