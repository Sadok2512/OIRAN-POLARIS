import { useEffect, useMemo, useState } from 'react';
import { Copy, Lock, Plus, Trash2, X } from 'lucide-react';
import { bpfForRole, type InterfaceRole } from '@/data/roleMapping';

export type ProbeKind = 'vprobe' | 'physical';

const ROLES: Exclude<InterfaceRole, null>[] = ['N2', 'N3', 'N4', 'S1', 'N6'];

interface InterfaceDraft {
  name: string;
  role: Exclude<InterfaceRole, null>;
  filter: string;
}

export function RegisterProbeDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const [kind, setKind] = useState<ProbeKind>('vprobe');
  const [name, setName] = useState('');
  const [host, setHost] = useState('');
  const [mgmtIp, setMgmtIp] = useState('');
  const [site, setSite] = useState('');
  const [notes, setNotes] = useState('');
  const [ifaces, setIfaces] = useState<InterfaceDraft[]>([
    { name: 'ens3', role: 'N2', filter: bpfForRole('N2') },
  ]);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (open) {
      setKind('vprobe');
      setName('');
      setHost('');
      setMgmtIp('');
      setSite('');
      setNotes('');
      setIfaces([{ name: 'ens3', role: 'N2', filter: bpfForRole('N2') }]);
      setCopied(false);
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handler = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onClose]);

  const probeId = useMemo(() => slugify(`${kind}-${name}`.trim() || `${kind}`), [kind, name]);

  const payload = useMemo(
    () => ({
      probe_id: probeId,
      probe_type: kind === 'vprobe' ? 'Virtual' : 'Physical',
      name: name.trim(),
      host: host.trim(),
      mgmt_ip: mgmtIp.trim() || null,
      site: site.trim() || null,
      notes: notes.trim() || null,
      interfaces: ifaces.map((iface) => ({
        interface: iface.name.trim(),
        role: iface.role,
        bpf_filter: iface.filter.trim(),
      })),
    }),
    [probeId, kind, name, host, mgmtIp, site, notes, ifaces],
  );

  const payloadJson = useMemo(() => JSON.stringify(payload, null, 2), [payload]);

  const errors: string[] = [];
  if (!name.trim()) errors.push('Name is required');
  if (!host.trim()) errors.push('Host / namespace is required');
  if (kind === 'physical' && !mgmtIp.trim()) errors.push('Management address is required for a physical probe');
  if (ifaces.length === 0) errors.push('At least one interface is required');
  const seen = new Set<string>();
  for (const iface of ifaces) {
    if (!iface.name.trim()) {
      errors.push('Interface name is required');
      break;
    }
    const key = iface.name.trim();
    if (seen.has(key)) {
      errors.push(`Duplicate interface "${key}"`);
      break;
    }
    seen.add(key);
  }

  if (!open) return null;

  function copyPayload() {
    if (typeof navigator === 'undefined' || !navigator.clipboard) return;
    void navigator.clipboard.writeText(payloadJson).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="register-probe-title"
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4"
      data-testid="register-probe-dialog"
    >
      <div className="ep-card w-full max-w-3xl p-5 flex flex-col gap-3 my-4">
        <header className="flex items-center justify-between">
          <div>
            <h2 id="register-probe-title" className="text-ep-lg font-semibold">
              Register probe
            </h2>
            <p className="text-ep-xs text-text-secondary">
              The backend <code className="mono">POST /probes</code> contract is not published
              yet; submit stays locked. The JSON payload below is what the UI will send
              once the route exists.
            </p>
          </div>
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={onClose}
            aria-label="Close"
          >
            <X width={13} height={13} />
          </button>
        </header>

        <section className="grid gap-3">
          <div
            role="radiogroup"
            aria-label="Probe type"
            className="flex gap-2"
            data-testid="register-probe-kind"
          >
            {(['vprobe', 'physical'] as ProbeKind[]).map((option) => (
              <label
                key={option}
                className={`ep-button ep-button-sm cursor-pointer ${
                  kind === option ? 'ep-button-primary' : ''
                }`}
              >
                <input
                  type="radio"
                  name="probe-kind"
                  value={option}
                  checked={kind === option}
                  onChange={() => setKind(option)}
                  className="sr-only"
                />
                {option === 'vprobe' ? 'vProbe' : 'Physical probe'}
              </label>
            ))}
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Name" required>
              <input
                className="ep-input"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder={kind === 'vprobe' ? 'Lab vProbe · site-A' : 'DC rack 3 probe'}
                data-testid="register-probe-name"
              />
            </Field>
            <Field label="probe_id (auto)">
              <input className="ep-input mono" value={probeId} readOnly data-testid="register-probe-id" />
            </Field>
            <Field label={kind === 'vprobe' ? 'Lab host' : 'Hostname'} required>
              <input
                className="ep-input mono"
                value={host}
                onChange={(event) => setHost(event.target.value)}
                placeholder={kind === 'vprobe' ? 'namespace.container.local' : 'hostname.corp.local'}
                data-testid="register-probe-host"
              />
            </Field>
            <Field
              label={kind === 'physical' ? 'Management address' : 'Management address (optional)'}
              required={kind === 'physical'}
            >
              <input
                className="ep-input mono"
                value={mgmtIp}
                onChange={(event) => setMgmtIp(event.target.value)}
                placeholder="10.77.0.1"
                data-testid="register-probe-mgmt"
              />
            </Field>
            <Field label="Site">
              <input
                className="ep-input"
                value={site}
                onChange={(event) => setSite(event.target.value)}
                placeholder="Lab A · rack 03"
              />
            </Field>
            <Field label="Notes">
              <input
                className="ep-input"
                value={notes}
                onChange={(event) => setNotes(event.target.value)}
                placeholder="Capture plane assignments, maintenance window…"
              />
            </Field>
          </div>
        </section>

        <section className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <h3 className="text-ep-sm font-semibold">Interfaces · {ifaces.length}</h3>
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={() =>
                setIfaces((current) => [
                  ...current,
                  { name: '', role: 'N3', filter: bpfForRole('N3') },
                ])
              }
              data-testid="register-probe-add-interface"
            >
              <Plus width={13} height={13} /> Add interface
            </button>
          </div>
          <table className="ep-table" data-testid="register-probe-interfaces">
            <thead>
              <tr>
                <th>Interface</th>
                <th>Role</th>
                <th>BPF filter</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {ifaces.map((iface, index) => (
                <tr key={index}>
                  <td>
                    <input
                      className="ep-input mono"
                      value={iface.name}
                      onChange={(event) =>
                        setIfaces((current) =>
                          current.map((item, i) =>
                            i === index ? { ...item, name: event.target.value } : item,
                          ),
                        )
                      }
                      placeholder="ens4"
                      aria-label={`Interface ${index + 1} name`}
                    />
                  </td>
                  <td>
                    <select
                      className="ep-input"
                      value={iface.role}
                      onChange={(event) => {
                        const role = event.target.value as Exclude<InterfaceRole, null>;
                        setIfaces((current) =>
                          current.map((item, i) =>
                            i === index
                              ? { ...item, role, filter: bpfForRole(role) }
                              : item,
                          ),
                        );
                      }}
                      aria-label={`Interface ${index + 1} role`}
                    >
                      {ROLES.map((role) => (
                        <option key={role} value={role}>
                          {role}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <input
                      className="ep-input mono"
                      value={iface.filter}
                      onChange={(event) =>
                        setIfaces((current) =>
                          current.map((item, i) =>
                            i === index ? { ...item, filter: event.target.value } : item,
                          ),
                        )
                      }
                      aria-label={`Interface ${index + 1} BPF filter`}
                    />
                  </td>
                  <td>
                    <button
                      type="button"
                      className="ep-button ep-button-sm ep-button-danger"
                      onClick={() =>
                        setIfaces((current) => current.filter((_, i) => i !== index))
                      }
                      aria-label={`Remove interface ${index + 1}`}
                      disabled={ifaces.length === 1}
                    >
                      <Trash2 width={13} height={13} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {errors.length > 0 && (
          <ul className="text-ep-xs text-error flex flex-col gap-0.5" data-testid="register-probe-errors">
            {errors.map((error, index) => (
              <li key={index}>· {error}</li>
            ))}
          </ul>
        )}

        <section
          className="border border-border rounded-md bg-canvas/40"
          data-testid="register-probe-payload"
        >
          <header className="flex items-center justify-between px-3 py-2 border-b border-border">
            <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
              Payload preview (POST /probes)
            </span>
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={copyPayload}
              data-testid="register-probe-copy"
            >
              <Copy width={13} height={13} />
              {copied ? 'Copied' : 'Copy'}
            </button>
          </header>
          <pre className="mono text-ep-xs p-3 overflow-x-auto max-h-56">
            {payloadJson}
          </pre>
        </section>

        <footer className="flex items-center justify-between gap-2 pt-2 border-t border-border">
          <span
            className="ep-badge border-warning/40 text-warning"
            data-testid="register-probe-lock-reason"
          >
            <Lock width={11} height={11} /> Backend pending: POST /probes
          </span>
          <div className="flex items-center gap-2">
            <button type="button" className="ep-button ep-button-sm" onClick={onClose}>
              Cancel
            </button>
            <button
              type="button"
              className="ep-button ep-button-sm ep-button-primary"
              disabled
              aria-disabled="true"
              title="POST /probes is not implemented by the backend; the UI never fabricates a success."
              data-testid="register-probe-submit"
            >
              Register (locked)
            </button>
          </div>
        </footer>
      </div>
    </div>
  );
}

function Field({
  label,
  required,
  children,
}: {
  label: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1 text-ep-sm">
      <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
        {label}
        {required && <span className="text-error ml-0.5">*</span>}
      </span>
      {children}
    </label>
  );
}

function slugify(input: string): string {
  return input
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'probe';
}
