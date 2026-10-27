# Network Topology — implementation

## Rendering stack

- **React Flow** (`@xyflow/react` 12.3.6) — nodes, edges, controls, minimap
- Custom node type `TelecomNode` — telecom-aware badge, status dot,
  evidence tag
- Edge rendering: smoothstep + conditional animation when the edge is
  tagged `DISCOVERED`
- CSS layer in `src/styles/globals.css` adds dark-mode overrides for
  React Flow (controls, minimap, background grid)

## Data pipeline

```
useProbes()        ─┐
useInterfaces()    ─┼──> buildTopology({ probes, interfaces })
                    │        │
                    │        └─> { nodes, edges }  (deterministic)
                    │
                    └── placeInColumn() lays out nodes by kind-column
```

`buildTopology` always emits the 5G SA scaffold (`UE → gNB → AMF → SMF →
UPF`) as `INFERRED` nodes so the view is readable even when the backend
has not returned any probe. Every backend-reported probe is added as
`DISCOVERED`; every interface is added as `DISCOVERED` and its edge to
the nearest NF (based on the plane prefix `N2`, `N3`, `N4`, `SBI`) is
tagged `CONFIGURED`.

### Evidence model

| Tag          | Source                                                           |
| ------------ | ---------------------------------------------------------------- |
| `DISCOVERED` | Returned by the OIRAN API (`/probes`, `/interfaces`)             |
| `CONFIGURED` | Derived from the plane name of a `DISCOVERED` interface          |
| `INFERRED`   | 5G SA reference scaffold added by the UI                         |
| `UNKNOWN`    | Reserved for backend-returned nodes with insufficient evidence   |

The topology never implies a link is physically verified: `UPF` and `AMF`
only receive a `CONFIGURED` edge from an interface the backend explicitly
reports. Pure scaffold edges carry the `INFERRED` tag.

## Interactions

Implemented:

- Zoom and pan (React Flow default)
- Fit View button (`Fit View`)
- Search node (prefix match on label + id → `fitView` on the match)
- Click to select a node (highlights the node + direct neighbours;
  non-neighbour nodes fade to 35 % opacity)
- Clear selection (button or pane click)
- Open right-side `TopologyInspector` (details, evidence, metadata)
- Collapse Inspector via its `X` button
- Fullscreen toggle via `document.fullscreenElement` API

### Inspector contents per node kind

| Kind                 | Fields                                                      |
| -------------------- | ----------------------------------------------------------- |
| `UE`                 | Scaffold only — no details beyond evidence                  |
| `GNB`/`AMF`/`SMF`/`UPF` | Scaffold only                                            |
| `PROBE_PHYSICAL/VIRTUAL` | Probe ID, host, capture state, CPU %                   |
| `INTERFACE`          | Linux device, capture point, live capture authorization     |

Sensitive management credentials are never shown; probes expose their
public `probe_id`, `host` and reported status, nothing more.

## Layout heuristic

```
Column index per kind (left → right):
  UE(0) → RAN(1) → GNB(2) → ENB(3) → AMF(4) → SMF(5) → OTHER_NF(6)
         → UPF(7) → PROBE_PHYSICAL(8) → PROBE_VIRTUAL(9) → INTERFACE(10)
```

Each column is sized at 220 px; nodes within a column stack vertically on
140 px spacing. The result is a readable left-to-right 5G SA topology with
probes/interfaces grouped as right-side leaves.

## Caveats

- Interface→NF association is heuristic (name prefix) when the backend
  does not supply a direct link. This is why those edges are tagged
  `CONFIGURED` rather than `DISCOVERED`.
- Multi-UE topologies would collapse into the single scaffold UE; the
  model allows adding multiple UE nodes if the backend reports them (not
  currently exposed by the API).
- Links between NFs (NG-C, SBI, N4, NG-U) are drawn as `INFERRED` because
  the OIRAN API does not independently confirm them. A future
  `/topology/links` endpoint would upgrade them to `DISCOVERED` or
  `CONFIGURED`.
