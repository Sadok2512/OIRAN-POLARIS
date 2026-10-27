const TOKEN_KEY = 'oiran.access_token';
const CHANNEL_NAME = 'oiran.operator.session';

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character]);
}

function secureTransport() {
  return window.isSecureContext === true ||
    window.location.protocol === 'https:' ||
    ['localhost', '127.0.0.1', '::1'].includes(window.location.hostname);
}

async function authMe(token) {
  const headers = new Headers({ Accept: 'application/json' });
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch('/api/v1/auth/me', {
    method: 'GET',
    credentials: 'omit',
    headers,
  });
  const body = await response.json().catch(() => null);
  if (!response.ok || !body?.data) throw new Error(`Authentication failed (HTTP ${response.status})`);
  return body.data;
}

class OiranOperatorLogin extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.auth = null;
    this.error = '';
    this.open = false;
    this.channel = typeof BroadcastChannel === 'function'
      ? new BroadcastChannel(CHANNEL_NAME)
      : null;
    if (this.channel) {
      this.channel.onmessage = (event) => {
        if (event.data?.type !== 'logout') return;
        sessionStorage.removeItem(TOKEN_KEY);
        window.location.reload();
      };
    }
  }

  connectedCallback() {
    this.refresh();
  }

  disconnectedCallback() {
    this.channel?.close();
  }

  async refresh() {
    const token = sessionStorage.getItem(TOKEN_KEY);
    try {
      this.auth = await authMe(token);
      if (token && !this.auth.authenticated) sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      this.auth = null;
    }
    this.render();
  }

  render() {
    const connected = this.auth?.authenticated === true;
    const role = this.auth?.role ?? 'viewer';
    const permissions = Array.isArray(this.auth?.permissions) ? this.auth.permissions : [];
    const safeRole = escapeHtml(role);
    const safePermissions = permissions.map(escapeHtml);
    const secure = secureTransport();
    this.shadowRoot.innerHTML = `
      <style>
        :host{font:500 12px/1.35 Inter,system-ui,sans-serif;color:inherit;display:inline-flex}
        button,input{font:inherit}button{border:1px solid #52627a;border-radius:6px;background:#17283f;color:#fff;padding:7px 10px;cursor:pointer}button[disabled]{opacity:.5;cursor:not-allowed}.connected{background:#087f5b}.backdrop{position:fixed;z-index:10000;inset:0;background:#0008;display:flex;align-items:center;justify-content:center;padding:20px}.dialog{width:min(440px,100%);background:#fff;color:#17283f;border-radius:8px;padding:20px;box-shadow:0 12px 40px #0006}.dialog h2{font-size:18px;margin:0 0 6px}.dialog p{color:#66758b}.dialog label{display:grid;gap:6px;margin:16px 0}.dialog input{border:1px solid #b8c2d1;border-radius:6px;padding:10px}.actions{display:flex;gap:8px;justify-content:flex-end}.error{color:#b42318}.permissions{font:12px/1.5 ui-monospace,monospace;overflow-wrap:anywhere}.hint{margin-left:6px;color:#d97706}
      </style>
      <button id="session" ${!connected && !secure ? 'disabled' : ''} class="${connected ? 'connected' : ''}" title="${connected ? safePermissions.join(', ') : secure ? 'Authenticate with the existing OIRAN Bearer token' : 'Use localhost:8020 through the private SSH tunnel'}">
        ${connected ? `Operator Connected · ${safeRole}` : 'Operator Login'}
      </button>
      ${!connected && !secure ? '<span class="hint">Private tunnel required</span>' : ''}
      ${this.open ? `<div class="backdrop" role="dialog" aria-modal="true" aria-labelledby="operator-title"><div class="dialog">
        <h2 id="operator-title">${connected ? 'Operator session' : 'Operator Login'}</h2>
        ${connected
          ? `<p>Role: <b>${safeRole}</b></p><p class="permissions">Permissions: ${safePermissions.length ? safePermissions.join(', ') : 'none reported'}</p><div class="actions"><button id="close">Close</button><button id="logout">Logout</button></div>`
          : `<p>Use the existing OIRAN Operator token. It remains in this browser session and is sent only in the Authorization header.</p><form id="login"><label>Operator Token<input id="token" type="password" autocomplete="off" required></label>${this.error ? `<p class="error" role="alert">${escapeHtml(this.error)}</p>` : ''}<div class="actions"><button type="button" id="close">Cancel</button><button type="submit">Connect</button></div></form>`}
      </div></div>` : ''}`;

    this.shadowRoot.getElementById('session')?.addEventListener('click', () => {
      this.open = true;
      this.error = '';
      this.render();
    });
    this.shadowRoot.getElementById('close')?.addEventListener('click', () => {
      this.open = false;
      this.error = '';
      this.render();
    });
    this.shadowRoot.getElementById('logout')?.addEventListener('click', () => {
      sessionStorage.removeItem(TOKEN_KEY);
      this.channel?.postMessage({ type: 'logout' });
      window.location.reload();
    });
    this.shadowRoot.getElementById('login')?.addEventListener('submit', async (event) => {
      event.preventDefault();
      const token = this.shadowRoot.getElementById('token')?.value ?? '';
      try {
        const result = await authMe(token);
        if (!result.authenticated || !['operator', 'administrator'].includes(result.role)) {
          throw new Error('The token was not recognized as an OIRAN Operator.');
        }
        sessionStorage.setItem(TOKEN_KEY, token);
        this.auth = result;
        this.open = false;
        this.error = '';
        window.location.reload();
      } catch (error) {
        sessionStorage.removeItem(TOKEN_KEY);
        this.error = error instanceof Error ? error.message : 'Operator authentication failed.';
        this.render();
      }
    });
  }
}

if (!customElements.get('oiran-operator-login')) {
  customElements.define('oiran-operator-login', OiranOperatorLogin);
}

function mount() {
  const slot = document.querySelector('[data-operator-auth-slot]') ?? document.querySelector('.topbar .user');
  if (!slot || slot.querySelector('oiran-operator-login')) return false;
  slot.replaceChildren(document.createElement('oiran-operator-login'));
  return true;
}

if (!mount()) {
  const observer = new MutationObserver(() => {
    if (mount()) observer.disconnect();
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
}

export { TOKEN_KEY, authMe, secureTransport };
