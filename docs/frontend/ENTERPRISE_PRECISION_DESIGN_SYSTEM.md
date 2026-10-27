# Enterprise Precision — design system reference

## Intent

Enterprise Precision is the shared visual language of the Telecom Platform
Portal and the OIRAN Probe Manager. It is a density-first, utility-forward
system that prioritizes operational clarity over decorative polish.

Reference points (direction only, no copied layouts or brand assets):

- Linear — spacing precision and keyboard affordances
- Vercel — typographic restraint
- Datadog — operational density
- Grafana — monitoring usability

Explicit non-goals:

- No glassmorphism, no neon glow, no decorative gradients
- No oversized hero cards, no marketing-style whitespace
- No ambient animation; motion is reserved for state transitions

## Design tokens

Tokens live in [`packages/ui/src/tokens.ts`](../shared/tokens.ts) and are mirrored
as CSS variables in each app's `src/styles/globals.css`.

### Color

| Role                | Light      | Dark       |
| ------------------- | ---------- | ---------- |
| Background          | `#F5F7FA`  | `#0B1220`  |
| Surface             | `#FFFFFF`  | `#152238`  |
| Sidebar             | `#F0F4F9`  | `#101B2C`  |
| Text primary        | `#17283F`  | `#E7F0FF`  |
| Text secondary      | `#66758B`  | `#94A3B8`  |
| Border              | `#DEE5ED`  | `#30415C`  |
| Primary action      | `#2563EB`  | `#3B82F6`  |
| Success             | `#059669`  | `#10B981`  |
| Warning             | `#D97706`  | `#F59E0B`  |
| Error               | `#DC2626`  | `#EF4444`  |

All colors are consumed through CSS variables (`var(--c-*)`) so Tailwind
classes stay theme-aware without re-compilation.

### Typography

- Family: Inter (loaded from `rsms.me/inter`), monospace fallback for
  numeric telemetry
- Body 13–14 px, tables 12–13 px, page heading 22–26 px
- `font-variant-numeric: tabular-nums` for every telemetry cell and the
  mono helper class
- Weights: 400 body, 500 emphasis, 600 headings, 700 reserved

### Spacing & elevation

- 4 px base; standard control height 40 px (`spacing.control`)
- Radii: `6 | 8 | 12` px — defaults to 8 px for cards/buttons
- Shadows: two tiers (`--shadow-elev-1` on cards, `--shadow-elev-2`
  reserved for popovers). Both are subtle (`rgba(0,0,0,0.04–0.08)`).

## Primitives

| Component             | Location                                                                 | Purpose                                                 |
| --------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------- |
| `AppLauncher`         | `apps/portal/src/components/AppLauncher.tsx`                              | Portal application card                                 |
| `PortalHeader/Footer` | `apps/portal/src/components/`                                             | Minimal shell for the Portal                            |
| `AppShell`            | `apps/probe-manager/src/layout/AppShell.tsx`                              | Sidebar + top bar + content outlet                      |
| `SidebarNavigation`   | `apps/probe-manager/src/layout/SidebarNavigation.tsx`                     | Section-grouped primary nav                             |
| `PageHeader`          | `apps/probe-manager/src/ui/PageHeader.tsx`                                | Eyebrow + title + description + actions                 |
| `StatusIndicator`     | `apps/probe-manager/src/ui/StatusIndicator.tsx`                           | Tone-aware dot + label                                  |
| `EmptyState`          | `apps/probe-manager/src/ui/EmptyErrorLoading.tsx`                         | Honest empty state                                      |
| `ErrorState`          | `apps/probe-manager/src/ui/EmptyErrorLoading.tsx`                         | Error with retry hook                                   |
| `LoadingSkeleton`     | `apps/probe-manager/src/ui/EmptyErrorLoading.tsx`                         | Loading placeholder                                     |
| `Unavailable`         | `apps/probe-manager/src/ui/EmptyErrorLoading.tsx`                         | Backend reported but omitted the value                  |
| `ConfirmDialog`       | `apps/probe-manager/src/ui/ConfirmDialog.tsx`                             | Blocking confirmation for destructive actions           |
| `ProbeInspector`      | `apps/probe-manager/src/components/ProbeInspector.tsx`                    | Right-side probe details drawer                         |
| `InterfaceInspector`  | `apps/probe-manager/src/components/InterfaceInspector.tsx`                | Right-side interface details drawer                     |
| `TopologyInspector`   | `apps/probe-manager/src/topology/TopologyInspector.tsx`                   | Topology node details drawer                            |
| `TelecomNode`         | `apps/probe-manager/src/topology/TelecomNode.tsx`                         | Custom React Flow node (UE / RAN / NF / probe / iface)  |

Shadcn/ui was intentionally **not** installed as a scaffold package because
the two apps only needed ~12 primitives — pulling the whole ui library would
have inflated the bundle and the surface area. The primitives above use the
same tokens and Radix-style keyboard affordances (focus-visible rings,
dialog focus trap, aria-radiogroup for the theme switch).

## State semantics

| Term            | Meaning                                                              |
| --------------- | -------------------------------------------------------------------- |
| `Not available` | Backend did not return a value for this field — never fabricate zero |
| `Unavailable`   | Backend acknowledged the resource exists but refused the measurement |
| `Empty`         | The backend returned 0 items; no data to display yet                 |
| `Loading`       | Request in flight — small inline label with spinner                  |
| `Error`         | Request failed — surface the status/code with a retry affordance     |

Evidence tags on topology nodes/edges follow the brief exactly:
`DISCOVERED`, `CONFIGURED`, `INFERRED`, `UNKNOWN`. Only `DISCOVERED` and
`CONFIGURED` reflect backend evidence; `INFERRED` means the UI anchored a
reference node to keep the view readable.

## Accessibility

- Theme switch uses `role="radiogroup"`/`role="radio"` with
  `aria-checked`; sidebar links use `aria-current="page"` through
  react-router's `NavLink` active state.
- Every interactive element has a visible focus ring
  (`:focus-visible { outline: 2px solid var(--c-primary) }`).
- Dialogs trap focus and restore on close; `aria-labelledby` points at the
  dialog title.
- Status indicators pass semantic `aria-label` strings matching the badge
  text so screen readers do not announce dots as "image".

## Responsive behavior

Both apps are validated at 1920×1080, 1440×900, 1280×800 and 1024×768
through Playwright (see `FRONTEND_TEST_REPORT.md`). The Portal grid steps
3 → 2 → 1 columns. The Probe Manager AppShell collapses the sidebar from
240 px → 56 px without clipping captions.
