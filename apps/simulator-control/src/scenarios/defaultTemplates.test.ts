import { describe, expect, it } from 'vitest';
import {
  DEFAULT_SCENARIO_TEMPLATES,
  scenarioFromSystemTemplate,
  templateSupport,
} from './defaultTemplates';

describe('default scenario templates', () => {
  it('mirrors all thirteen IDs from the finalized ANR1 contract', () => {
    expect(DEFAULT_SCENARIO_TEMPLATES).toHaveLength(13);
    expect(DEFAULT_SCENARIO_TEMPLATES.filter((item) => item.rat === 'LTE')).toHaveLength(6);
    expect(DEFAULT_SCENARIO_TEMPLATES.filter((item) => item.rat === '5G_SA')).toHaveLength(7);
    expect(new Set(DEFAULT_SCENARIO_TEMPLATES.map((item) => item.id)).size).toBe(13);
    expect(DEFAULT_SCENARIO_TEMPLATES.every((item) => item.system)).toBe(true);
  });

  it('keeps the backend support decisions authoritative', () => {
    const lte = DEFAULT_SCENARIO_TEMPLATES.find((item) => item.id === 'tpl-lte-attach')!;
    expect(templateSupport(lte)).toBe('CERTIFICATION_REQUIRED');
    const fiveG = DEFAULT_SCENARIO_TEMPLATES.find((item) => item.id === 'tpl-5g-full-session')!;
    expect(templateSupport(fiveG)).toBe('BACKEND_REQUIRED');
  });

  it('creates a detached editable Scenario without mutating the system definition', () => {
    const source = DEFAULT_SCENARIO_TEMPLATES[0];
    const draft = scenarioFromSystemTemplate(source);
    draft.name = 'Changed copy';
    draft.steps[0].params.timeout_s = { mode: 'fixed', value: 42 };
    expect(draft.id).toBe(source.id);
    expect(draft.name).not.toBe(source.name);
    expect(source.definition.steps[0].parameters).toEqual({});
  });
});
