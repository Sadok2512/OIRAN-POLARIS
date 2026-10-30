// 0.5.0 — StepEditor REPEAT behaviour.
//
// We only cover what is new in 0.5.0:
//   * REPEAT exposes a nested-step palette and renders its children.
//   * The nested palette filters out REPEAT once MAX_REPEAT_NESTING is hit.
//   * Locked step types (TRAFFIC_DL, IMS_REGISTER, VOICE_CALL) render
//     the backend-note badge verbatim so the operator sees the exact code.

import { describe, expect, it } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { StepEditor } from './StepEditor';
import {
  MAX_REPEAT_NESTING,
  newStepId,
  type ScenarioStep,
} from '@/scenarios/model';

function Harness({ initial }: { initial: ScenarioStep }) {
  const [step, setStep] = useState<ScenarioStep>(initial);
  return (
    <StepEditor
      index={1}
      step={step}
      onUpdate={(patch) => setStep((prev) => ({ ...prev, ...patch }))}
      onParam={(key, value) =>
        setStep((prev) => ({
          ...prev,
          params: value ? { ...prev.params, [key]: value } : { ...prev.params, [key]: undefined },
        }))
      }
    />
  );
}

describe('StepEditor — REPEAT nesting (0.5.0)', () => {
  it('renders a palette for the nested block and adds a child step through it', async () => {
    const user = userEvent.setup();
    const repeat: ScenarioStep = {
      id: newStepId(),
      kind: 'REPEAT',
      params: { loop_count: { mode: 'fixed', value: 3 } },
      steps: [],
    };
    render(<Harness initial={repeat} />);

    // The nested palette exists at depth 0 and offers all step kinds, including REPEAT
    // because depth + 1 = 1 < MAX_REPEAT_NESTING (=2) so a nested REPEAT is still legal.
    const palette = screen.getByTestId(`repeat-palette-${repeat.id}`);
    expect(within(palette).getByTestId(`repeat-add-REPEAT-${repeat.id}`)).toBeInTheDocument();
    expect(within(palette).getByTestId(`repeat-add-TRAFFIC_UL-${repeat.id}`)).toBeInTheDocument();

    // No child yet.
    expect(screen.getByText('No nested step yet.')).toBeInTheDocument();

    // Add a TRAFFIC_UL inside the repeat.
    await user.click(screen.getByTestId(`repeat-add-TRAFFIC_UL-${repeat.id}`));
    // The nested editor renders at depth 1.
    const nested = await screen.findAllByTestId('step-editor-depth-1');
    expect(nested).toHaveLength(1);
    // That nested editor is seeded with the TRAFFIC_UL kind.
    const kindSelect = within(nested[0]).getByRole('combobox', { name: /Step \d+ kind/ }) as HTMLSelectElement;
    expect(kindSelect.value).toBe('TRAFFIC_UL');
  });

  it('refuses to offer a deeper REPEAT inside a nested REPEAT (MAX_REPEAT_NESTING = 2)', async () => {
    expect(MAX_REPEAT_NESTING).toBe(2);
    const inner: ScenarioStep = {
      id: 'inner-id',
      kind: 'REPEAT',
      params: { loop_count: { mode: 'fixed', value: 2 } },
      steps: [],
    };
    const outer: ScenarioStep = {
      id: 'outer-id',
      kind: 'REPEAT',
      params: { loop_count: { mode: 'fixed', value: 2 } },
      steps: [inner],
    };
    render(<Harness initial={outer} />);

    // Inner palette (depth 1 → children would be at depth 2 == MAX) must NOT list REPEAT.
    const innerPalette = screen.getByTestId(`repeat-palette-${inner.id}`);
    expect(within(innerPalette).queryByTestId(`repeat-add-REPEAT-${inner.id}`)).toBeNull();
    // It still offers the leaf step kinds.
    expect(within(innerPalette).getByTestId(`repeat-add-TRAFFIC_UL-${inner.id}`)).toBeInTheDocument();
  });

  it('shows the backend-note verbatim on locked step kinds (TRAFFIC_DL, IMS_REGISTER, VOICE_CALL)', () => {
    const locked: ScenarioStep[] = [
      { id: 'a', kind: 'TRAFFIC_DL', params: {} },
      { id: 'b', kind: 'IMS_REGISTER', params: {} },
      { id: 'c', kind: 'VOICE_CALL', params: {} },
    ];
    for (const step of locked) {
      const { unmount } = render(<Harness initial={step} />);
      const notice = screen.getByTestId('step-backend-notice');
      if (step.kind === 'TRAFFIC_DL') expect(notice).toHaveTextContent('DL_SENDER_NOT_AVAILABLE');
      else expect(notice).toHaveTextContent('IMS_NOT_AVAILABLE');
      unmount();
    }
  });
});
