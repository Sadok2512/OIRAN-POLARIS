import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { EvidenceBadge } from './EvidenceBadge';

describe('EvidenceBadge', () => {
  it.each(['EXACT', 'STRONG', 'POSSIBLE', 'UNKNOWN'] as const)(
    'renders %s with the matching testid',
    (confidence) => {
      render(<EvidenceBadge confidence={confidence} />);
      expect(screen.getByTestId(`evidence-${confidence}`)).toHaveTextContent(
        confidence,
      );
    },
  );

  it('falls back to UNKNOWN when the confidence is undefined', () => {
    render(<EvidenceBadge confidence={undefined} />);
    expect(screen.getByTestId('evidence-UNKNOWN')).toHaveTextContent('UNKNOWN');
  });

  it('never promotes STRONG to EXACT visually (uses the EXACT tone only for EXACT)', () => {
    const { getByTestId } = render(<EvidenceBadge confidence="STRONG" />);
    const className = getByTestId('evidence-STRONG').className;
    expect(className).toMatch(/text-primary/);
    expect(className).not.toMatch(/text-success/);
  });
});
