import { FormEvent, useState } from 'react';
import { LogIn, LogOut, X } from 'lucide-react';
import { useQueryClient } from '@tanstack/react-query';
import { api, setAccessToken } from '@shared/api';
import type { AuthState } from '@shared/types';
import { useAuth } from '@/data/queries';

export function secureOperatorTransport(): boolean {
  if (typeof window === 'undefined') return false;
  return (
    window.isSecureContext === true ||
    window.location.protocol === 'https:' ||
    ['localhost', '127.0.0.1', '::1'].includes(window.location.hostname)
  );
}

export function OperatorAuth({
  secureTransport = secureOperatorTransport(),
}: {
  secureTransport?: boolean;
}) {
  const auth = useAuth();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);

  async function signIn(event: FormEvent) {
    event.preventDefault();
    if (!secureTransport || !token || pending) return;
    setPending(true);
    setError('');
    setAccessToken('oiran', token);
    try {
      const result = await api<AuthState>('/auth/me', { authScope: 'oiran' });
      if (!result.data.authenticated || !result.data.capture_control) {
        throw new Error('The OIRAN API did not grant Operator capture permission.');
      }
      setToken('');
      setOpen(false);
      await queryClient.invalidateQueries({ queryKey: ['auth'] });
    } catch (reason) {
      setAccessToken('oiran', null);
      setToken('');
      setError((reason as Error).message || 'Operator authentication failed.');
      await queryClient.invalidateQueries({ queryKey: ['auth'] });
    } finally {
      setPending(false);
    }
  }

  async function signOut() {
    setAccessToken('oiran', null);
    setToken('');
    setError('');
    setOpen(false);
    await queryClient.invalidateQueries({ queryKey: ['auth'] });
  }

  if (auth.data?.authenticated) {
    return (
      <button
        type="button"
        className="ep-button ep-button-sm"
        onClick={() => void signOut()}
        aria-label="Operator logout"
      >
        <LogOut width={14} height={14} aria-hidden="true" />
        Sign out · {auth.data.role}
      </button>
    );
  }

  return (
    <>
      <button
        type="button"
        className="ep-button ep-button-sm"
        disabled={!secureTransport}
        title={secureTransport ? 'Authenticate with an existing OIRAN Operator token' : 'HTTPS or a private localhost tunnel is required'}
        onClick={() => {
          setError('');
          setOpen(true);
        }}
      >
        <LogIn width={14} height={14} aria-hidden="true" />
        Operator Login
      </button>
      {!secureTransport && (
        <span className="text-ep-xs text-warning" data-testid="https-required">
          HTTPS required
        </span>
      )}
      {open && secureTransport && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="operator-login-title"
        >
          <section className="ep-card w-full max-w-md p-5" aria-live="polite">
            <header className="flex items-start justify-between gap-4">
              <div>
                <h2 id="operator-login-title" className="text-ep-lg font-semibold">
                  Operator Login
                </h2>
                <p className="mt-1 text-ep-sm text-text-secondary">
                  Use an existing OIRAN Operator or Administrator token. It remains in this browser session only.
                </p>
              </div>
              <button
                type="button"
                className="ep-button ep-button-sm"
                aria-label="Close Operator Login"
                onClick={() => {
                  setToken('');
                  setError('');
                  setOpen(false);
                }}
              >
                <X width={14} height={14} aria-hidden="true" />
              </button>
            </header>
            <form className="mt-4 flex flex-col gap-3" onSubmit={(event) => void signIn(event)}>
              <label className="flex flex-col gap-1 text-ep-sm">
                Operator access token
                <input
                  className="ep-input"
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  value={token}
                  onChange={(event) => setToken(event.target.value)}
                  required
                />
              </label>
              {error && <p className="text-ep-sm text-error" role="alert">{error}</p>}
              <button
                type="submit"
                className="ep-button ep-button-primary"
                disabled={pending || !token}
              >
                {pending ? 'Validating permissions…' : 'Validate Operator permissions'}
              </button>
            </form>
          </section>
        </div>
      )}
    </>
  );
}
