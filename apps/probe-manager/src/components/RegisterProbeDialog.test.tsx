import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RegisterProbeDialog } from './RegisterProbeDialog';

describe('RegisterProbeDialog — locked (POST /probes pending)', () => {
  it('renders the lock badge and keeps the submit button disabled', async () => {
    render(<RegisterProbeDialog open onClose={() => undefined} />);
    expect(screen.getByTestId('register-probe-lock-reason').textContent).toMatch(
      /Backend pending: POST \/probes/,
    );
    expect(screen.getByTestId('register-probe-submit')).toBeDisabled();
  });

  it('derives a slug probe_id from "<type>-<name>"', async () => {
    const user = userEvent.setup();
    render(<RegisterProbeDialog open onClose={() => undefined} />);
    await user.type(screen.getByTestId('register-probe-name'), 'Edge Lab · Site A');
    expect((screen.getByTestId('register-probe-id') as HTMLInputElement).value).toBe(
      'vprobe-edge-lab-site-a',
    );
  });

  it('rewrites the BPF filter when the role changes (N2 → N3)', async () => {
    const user = userEvent.setup();
    render(<RegisterProbeDialog open onClose={() => undefined} />);
    const roleSelect = screen.getByLabelText('Interface 1 role');
    const bpfInput = screen.getByLabelText('Interface 1 BPF filter') as HTMLInputElement;
    expect(bpfInput.value).toBe('sctp port 38412'); // N2 default
    await user.selectOptions(roleSelect, 'N3');
    expect(bpfInput.value).toBe('udp port 2152');
  });

  it('reflects the current type radio in the payload preview', async () => {
    const user = userEvent.setup();
    render(<RegisterProbeDialog open onClose={() => undefined} />);
    const payload = () =>
      screen.getByTestId('register-probe-payload').querySelector('pre')!.textContent ?? '';
    expect(payload()).toContain('"probe_type": "Virtual"');
    await user.click(screen.getByRole('radio', { name: /physical/i }));
    expect(payload()).toContain('"probe_type": "Physical"');
  });

  it('surfaces a Copy button and renders the payload JSON inline', () => {
    render(<RegisterProbeDialog open onClose={() => undefined} />);
    const pre = screen.getByTestId('register-probe-payload').querySelector('pre');
    expect(pre).not.toBeNull();
    expect(pre!.textContent).toMatch(/"probe_id":\s*"vprobe"/);
    expect(screen.getByTestId('register-probe-copy')).toBeInTheDocument();
  });
});
