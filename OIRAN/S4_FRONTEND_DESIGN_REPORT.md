# S4 Frontend Design Report

## Design system

The application uses white analytical surfaces on `#F5F7FA`, deep navy navigation (`#14263D`), electric-blue actions (`#2878E3`), compact system typography and monospace identifiers. Success, partial and failure semantics use distinct accessible tones; decoding success is not treated as procedure success.

The shared shell provides module-registry navigation, breadcrumbs, environment/technology selectors, connection state, theme switch and user controls. The sidebar collapses without overlaying the workspace. Filters and selected session IDs remain URL-addressable.

## Pages

- **Probe Manager:** observed vProbe, manifest-derived N2/N3/N4 interfaces, sortable/searchable PCAP library, checksum inspector and explicitly disabled capture controls.
- **Session Explorer:** one real session, compact table, six detail tabs and a strict background-event view.
- **Call Flow Viewer:** resizable procedure/canvas/inspector panels, SVG lifelines and arrows, zoom, filters, session/all-event modes and five inspector tabs.
- **Correlation Studio:** evidence KPIs, selectable graph/table edges, exact rule/version/packet evidence and visible unmatched/ambiguous/background tabs.

## Visual verification

Eight browser screenshots under `S4_UI_SCREENSHOTS/` cover all four pages at 1440×900 and 1920×1080. Automated assertions found no document-level horizontal overflow. Manual inspection confirmed aligned panels, readable tables, distinct background semantics and correct message/lifeline placement. Inner analytical canvases deliberately scroll when their content exceeds the panel.

Dark mode is available, while light mode remains the default. Essential controls have visible keyboard focus. The application is desktop-oriented; widths below 1180 px are outside the S4 target.
