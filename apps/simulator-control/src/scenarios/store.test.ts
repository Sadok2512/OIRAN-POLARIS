import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  _reset,
  assignScenario,
  clearAssignment,
  deleteScenario,
  duplicateScenario,
  getAssignment,
  getScenario,
  listAssignments,
  listScenarios,
  saveScenario,
} from './store';
import { emptyScenario } from './model';

beforeEach(() => _reset());
afterEach(() => _reset());

describe('ScenarioStore — CRUD', () => {
  it('saves a new scenario and returns version 1 createdAt=now', () => {
    const saved = saveScenario(emptyScenario('alpha'));
    expect(listScenarios()).toHaveLength(1);
    expect(saved.version).toBe(1);
    expect(saved.name).toBe('alpha');
  });

  it('increments the version on each save', () => {
    const first = saveScenario(emptyScenario('beta'));
    const second = saveScenario({ ...first, description: 'edit 1' });
    const third = saveScenario({ ...second, description: 'edit 2' });
    expect(second.version).toBe(first.version + 1);
    expect(third.version).toBe(second.version + 1);
  });

  it('does not duplicate the stored entry when saving twice with the same id', () => {
    const first = saveScenario(emptyScenario('gamma'));
    saveScenario({ ...first, name: 'gamma renamed' });
    const list = listScenarios();
    expect(list).toHaveLength(1);
    expect(list[0].name).toBe('gamma renamed');
  });

  it('duplicates a scenario with a fresh id, name suffixed with (copy) and version=1', () => {
    const source = saveScenario(emptyScenario('delta'));
    const copy = duplicateScenario(source.id);
    expect(copy).not.toBeNull();
    expect(copy!.id).not.toBe(source.id);
    expect(copy!.name).toBe('delta (copy)');
    expect(copy!.version).toBe(1);
    expect(listScenarios()).toHaveLength(2);
  });

  it('deletes a scenario and cascades to its assignments', () => {
    const saved = saveScenario(emptyScenario('epsilon'));
    assignScenario('ue-1', saved.id, true);
    expect(listAssignments()).toHaveLength(1);
    deleteScenario(saved.id);
    expect(getScenario(saved.id)).toBeNull();
    expect(listAssignments()).toHaveLength(0);
  });
});

describe('AssignmentStore', () => {
  it('replaces an existing assignment for the same UE', () => {
    const scenarioA = saveScenario(emptyScenario('A'));
    const scenarioB = saveScenario(emptyScenario('B'));
    assignScenario('ue-1', scenarioA.id, false);
    assignScenario('ue-1', scenarioB.id, true);
    const assignment = getAssignment('ue-1');
    expect(assignment?.scenarioId).toBe(scenarioB.id);
    expect(assignment?.autoRun).toBe(true);
    expect(listAssignments()).toHaveLength(1);
  });

  it('supports multiple UEs assigned to different scenarios', () => {
    const scenarioA = saveScenario(emptyScenario('A'));
    const scenarioB = saveScenario(emptyScenario('B'));
    assignScenario('ue-1', scenarioA.id, false);
    assignScenario('ue-2', scenarioB.id, true);
    const list = listAssignments();
    expect(list).toHaveLength(2);
    expect(list.find((a) => a.ueId === 'ue-1')?.scenarioId).toBe(scenarioA.id);
    expect(list.find((a) => a.ueId === 'ue-2')?.scenarioId).toBe(scenarioB.id);
  });

  it('clears a single assignment without touching the others', () => {
    const scenarioA = saveScenario(emptyScenario('A'));
    assignScenario('ue-1', scenarioA.id, false);
    assignScenario('ue-2', scenarioA.id, true);
    clearAssignment('ue-1');
    expect(getAssignment('ue-1')).toBeNull();
    expect(getAssignment('ue-2')?.scenarioId).toBe(scenarioA.id);
  });
});
