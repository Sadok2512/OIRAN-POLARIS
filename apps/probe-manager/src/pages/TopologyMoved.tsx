import { ArrowRight, Network } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';

// The topology view is owned by POLARIS Simulator Control (apps/simulator-control)
// as of LOT 1. Probe Manager keeps a stub so an old bookmark lands on a page
// explaining the move — no automatic redirect to an external host (we don't
// want the browser to leave the Probe Manager preview without consent).
const POLARIS_TOPOLOGY_PATH = '/simulator/network/topology';

export function TopologyMovedPage() {
  return (
    <>
      <PageHeader
        eyebrow="Operations"
        title="Network Topology"
        description="The topology view has moved to POLARIS Simulator Control. Probe Manager now manages probes only (vProbe + physical, N interfaces per probe)."
      />
      <section
        className="ep-card p-5 flex flex-col gap-3 max-w-xl"
        data-testid="topology-moved"
      >
        <Network className="text-primary" width={28} height={28} aria-hidden="true" />
        <h2 className="text-ep-md font-semibold">Topology is in POLARIS now</h2>
        <p className="text-ep-sm text-text-secondary">
          Open <code className="mono">{POLARIS_TOPOLOGY_PATH}</code> in Simulator Control to see
          Core · Open5GS → gNB/eNB → UE. The data is composed client-side from{' '}
          <code className="mono">GET /lab</code>, <code className="mono">GET /nodes</code> and{' '}
          <code className="mono">GET /ues</code>; the probe fleet (this app) does not render it anymore.
        </p>
        <a
          className="ep-button ep-button-sm ep-button-primary self-start"
          href={POLARIS_TOPOLOGY_PATH}
          data-testid="topology-moved-link"
        >
          Open POLARIS Topology <ArrowRight width={13} height={13} aria-hidden="true" />
        </a>
      </section>
    </>
  );
}
