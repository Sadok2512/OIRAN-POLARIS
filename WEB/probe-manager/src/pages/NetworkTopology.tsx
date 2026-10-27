import { useMemo, useRef, useState } from 'react';
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Node,
} from '@xyflow/react';
import { Maximize2, Minimize2, Search } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from '@/ui/EmptyErrorLoading';
import { buildTopology } from '@/topology/buildTopology';
import { TelecomNode } from '@/topology/TelecomNode';
import { TopologyInspector } from '@/topology/TopologyInspector';
import type { TopologyNodeData } from '@/topology/types';
import { useInterfaces, useProbes } from '@/data/queries';

const NODE_TYPES = { telecom: TelecomNode };

function TopologyCanvas({
  nodes,
  edges,
  onSelect,
  selected,
}: {
  nodes: ReturnType<typeof buildTopology>['nodes'];
  edges: ReturnType<typeof buildTopology>['edges'];
  onSelect: (node: Node<TopologyNodeData> | null) => void;
  selected: Node<TopologyNodeData> | null;
}) {
  const flow = useReactFlow();
  const [search, setSearch] = useState('');

  function focusSearch() {
    const query = search.trim().toLowerCase();
    if (!query) return;
    const match = nodes.find((node) =>
      `${node.data.label} ${node.id}`.toLowerCase().includes(query),
    );
    if (match) {
      onSelect(match);
      flow.fitView({ nodes: [{ id: match.id }], padding: 0.4, duration: 300 });
    }
  }

  const highlighted = useMemo(() => {
    if (!selected) return new Set<string>();
    const neighbours = new Set<string>([selected.id]);
    for (const edge of edges) {
      if (edge.source === selected.id) neighbours.add(edge.target);
      if (edge.target === selected.id) neighbours.add(edge.source);
    }
    return neighbours;
  }, [edges, selected]);

  const styledEdges = useMemo(
    () =>
      edges.map((edge) => ({
        ...edge,
        style: {
          strokeWidth: highlighted.has(edge.source) && highlighted.has(edge.target) ? 2 : 1,
          opacity: selected && !(highlighted.has(edge.source) && highlighted.has(edge.target)) ? 0.3 : 1,
        },
      })),
    [edges, highlighted, selected],
  );

  const styledNodes = useMemo(
    () =>
      nodes.map((node) => ({
        ...node,
        style: {
          opacity: selected && !highlighted.has(node.id) ? 0.35 : 1,
        },
      })),
    [nodes, highlighted, selected],
  );

  return (
    <>
      <div className="absolute top-3 left-3 z-10 flex items-center gap-2">
        <label className="relative">
          <Search
            className="absolute left-2 top-1/2 -translate-y-1/2 text-text-secondary"
            width={14}
            height={14}
            aria-hidden="true"
          />
          <input
            className="ep-input pl-7 h-8"
            placeholder="Search node"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') focusSearch();
            }}
            aria-label="Search topology nodes"
            data-testid="topology-search"
          />
        </label>
        <button
          type="button"
          className="ep-button ep-button-sm"
          onClick={() => flow.fitView({ padding: 0.2, duration: 300 })}
          data-testid="topology-fit-view"
        >
          Fit View
        </button>
        <button
          type="button"
          className="ep-button ep-button-sm"
          onClick={() => onSelect(null)}
          data-testid="topology-clear"
        >
          Clear selection
        </button>
      </div>
      <ReactFlow
        nodes={styledNodes}
        edges={styledEdges}
        nodeTypes={NODE_TYPES}
        fitView
        onNodeClick={(_event, node) => onSelect(node as Node<TopologyNodeData>)}
        onPaneClick={() => onSelect(null)}
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={16} />
        <Controls showInteractive={false} position="bottom-left" />
        <MiniMap pannable zoomable position="bottom-right" />
      </ReactFlow>
    </>
  );
}

export function NetworkTopologyPage() {
  const probes = useProbes();
  const interfaces = useInterfaces();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const [selected, setSelected] = useState<Node<TopologyNodeData> | null>(null);

  const graph = useMemo(
    () =>
      buildTopology({
        probes: probes.data,
        interfaces: interfaces.data,
      }),
    [probes.data, interfaces.data],
  );

  const discovered = graph.nodes.filter(
    (node) => node.data.evidence === 'DISCOVERED',
  ).length;
  const inferred = graph.nodes.filter(
    (node) => node.data.evidence === 'INFERRED',
  ).length;

  const toggleFullscreen = () => {
    if (!containerRef.current) return;
    if (!document.fullscreenElement) {
      containerRef.current.requestFullscreen().then(() => setFullscreen(true));
    } else {
      document.exitFullscreen().then(() => setFullscreen(false));
    }
  };

  return (
    <>
      <PageHeader
        eyebrow="Operations"
        title="Network Topology"
        description="Interactive view of the discovered network. Nodes with evidence 'DISCOVERED' or 'CONFIGURED' come from the backend; 'INFERRED' nodes anchor the 5G SA scaffold."
        actions={
          <div className="flex items-center gap-2">
            <StatusIndicator
              state="DISCOVERED"
              label={`${discovered} discovered`}
              tone="success"
            />
            <StatusIndicator
              state="INFERRED"
              label={`${inferred} inferred`}
              tone="neutral"
            />
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={toggleFullscreen}
              data-testid="topology-fullscreen"
            >
              {fullscreen ? (
                <>
                  <Minimize2 width={13} height={13} aria-hidden="true" />
                  Exit
                </>
              ) : (
                <>
                  <Maximize2 width={13} height={13} aria-hidden="true" />
                  Fullscreen
                </>
              )}
            </button>
          </div>
        }
      />

      {probes.isLoading || interfaces.isLoading ? (
        <LoadingSkeleton label="Building topology" />
      ) : probes.error ? (
        <ErrorState
          title="Could not load probes"
          detail={(probes.error as Error).message}
          onRetry={() => void probes.refetch()}
        />
      ) : !graph.nodes.length ? (
        <EmptyState
          title="No topology to render"
          description="The scaffold could not be built. Verify the API connection."
        />
      ) : (
        <div
          ref={containerRef}
          className="ep-card overflow-hidden grid grid-cols-[minmax(0,1fr)_320px] h-[70vh] relative"
          data-testid="topology-canvas"
        >
          <div className="relative">
            <ReactFlowProvider>
              <TopologyCanvas
                nodes={graph.nodes}
                edges={graph.edges}
                onSelect={setSelected}
                selected={selected}
              />
            </ReactFlowProvider>
          </div>
          <TopologyInspector node={selected} onClose={() => setSelected(null)} />
        </div>
      )}
    </>
  );
}
