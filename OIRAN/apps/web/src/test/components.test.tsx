import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';
import { InspectorTabs } from '../components/InspectorTabs';
import { MetricStrip } from '../components/MetricStrip';
import { Pagination } from '../components/Pagination';

describe('shared analytical components', () => {
  it('renders protocol status without inflating it', () => {
    render(<StatusBadge value="PARTIAL" />);
    expect(screen.getByText('PARTIAL')).toHaveClass('status-partial');
  });

  it('renders loading and empty states accessibly', () => {
    const { rerender } = render(<LoadingState />);
    expect(screen.getByText(/loading certified data/i)).toBeInTheDocument();
    rerender(<EmptyState title="No matching messages">Preserved filters</EmptyState>);
    expect(screen.getByText('No matching messages')).toBeInTheDocument();
  });

  it('retries controlled errors', async () => {
    const retry = vi.fn();
    render(<ErrorState error={new Error('API unavailable')} retry={retry} />);
    await userEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(retry).toHaveBeenCalledOnce();
  });

  it('changes inspector tab content', async () => {
    render(<InspectorTabs tabs={[{ id: 'one', label: 'Overview', content: <span>overview body</span> }, { id: 'two', label: 'Provenance', content: <span>packet 27</span> }]} />);
    expect(screen.getByText('overview body')).toBeVisible();
    await userEvent.click(screen.getByRole('tab', { name: 'Provenance' }));
    expect(screen.getByText('packet 27')).toBeVisible();
  });

  it('renders only measured metrics', () => {
    render(<MetricStrip items={[{ label: 'Source events', value: 54 }, { label: 'Correlation edges', value: 12 }]} />);
    expect(screen.getByText('54')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
  });

  it('paginates using supplied server metadata', async () => {
    const change = vi.fn();
    render(<Pagination page={1} totalPages={3} onChange={change} />);
    await userEvent.click(screen.getByRole('button', { name: /next/i }));
    expect(change).toHaveBeenCalledWith(2);
  });
});
