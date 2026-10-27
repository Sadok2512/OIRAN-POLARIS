import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { OperatorAuth } from './OperatorAuth';

function respond(data: unknown) {
  return new Response(JSON.stringify({ data, meta: { api_version: '2.3.0' } }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function renderAuth(secureTransport: boolean) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <OperatorAuth secureTransport={secureTransport} />
    </QueryClientProvider>,
  );
}

const viewer = {
  authenticated: false,
  role: 'viewer',
  permissions: ['platform.read'],
  capture_control: false,
  capture_execution_enabled: true,
  reason: 'PUBLIC_VIEWER_OR_INVALID_TOKEN',
};

const operator = {
  authenticated: true,
  role: 'operator',
  permissions: ['platform.read', 'captures.control'],
  capture_control: true,
  capture_execution_enabled: true,
  reason: 'AUTHENTICATED_OPERATOR',
};

beforeEach(() => {
  sessionStorage.clear();
});

describe('OperatorAuth', () => {
  it('keeps login disabled on public HTTP', async () => {
    globalThis.fetch = vi.fn(async () => respond(viewer)) as unknown as typeof fetch;
    renderAuth(false);
    expect(await screen.findByRole('button', { name: 'Operator Login' })).toBeDisabled();
    expect(screen.getByTestId('https-required')).toBeInTheDocument();
  });

  it('validates an existing token with auth/me and supports local logout', async () => {
    globalThis.fetch = vi.fn(async (_input, init) => {
      const authorization = new Headers(init?.headers).get('Authorization');
      return respond(authorization ? operator : viewer);
    }) as unknown as typeof fetch;
    const user = userEvent.setup();
    renderAuth(true);

    await user.click(await screen.findByRole('button', { name: 'Operator Login' }));
    const input = screen.getByLabelText('Operator access token');
    await user.type(input, 'existing-operator-example');
    await user.click(screen.getByRole('button', { name: 'Validate Operator permissions' }));

    expect(await screen.findByRole('button', { name: 'Operator logout' })).toBeInTheDocument();
    expect(sessionStorage.getItem('oiran.access_token')).toBe('existing-operator-example');
    expect(screen.queryByDisplayValue('existing-operator-example')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Operator logout' }));
    await waitFor(() => expect(sessionStorage.getItem('oiran.access_token')).toBeNull());
    expect(await screen.findByRole('button', { name: 'Operator Login' })).toBeInTheDocument();
  });

  it('clears a token that does not receive capture permission', async () => {
    globalThis.fetch = vi.fn(async () => respond(viewer)) as unknown as typeof fetch;
    const user = userEvent.setup();
    renderAuth(true);

    await user.click(await screen.findByRole('button', { name: 'Operator Login' }));
    await user.type(screen.getByLabelText('Operator access token'), 'invalid-example');
    await user.click(screen.getByRole('button', { name: 'Validate Operator permissions' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('did not grant Operator capture permission');
    expect(sessionStorage.getItem('oiran.access_token')).toBeNull();
    expect(screen.queryByDisplayValue('invalid-example')).not.toBeInTheDocument();
  });
});
