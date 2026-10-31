import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { TechnologySelector } from './TechnologySelector';

describe('TechnologySelector', () => {
  it('shows both simulators and selects LTE explicitly', async () => {
    const onChange = vi.fn();
    render(<TechnologySelector value="5G_SA" onChange={onChange} />);

    expect(screen.getByRole('button', { name: '5G SA — UERANSIM' })).toHaveAttribute('aria-pressed', 'true');
    await userEvent.click(screen.getByRole('button', { name: 'LTE 4G — srsRAN' }));

    expect(onChange).toHaveBeenCalledOnce();
    expect(onChange).toHaveBeenCalledWith('LTE');
  });
});
