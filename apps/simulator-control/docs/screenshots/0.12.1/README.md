# simulator-control 0.12.1 — captures

Side-by-side mockup vs implementation screenshots at 1440×900, light and
dark themes.

## UE Manager

| File | Content |
| --- | --- |
| `ue-manager/mockup.light.png` | Mockup `polaris-control.html` (origin/docs/ui-mockups @ 48dea75), UE Manager tab, light theme |
| `ue-manager/impl.light.png` | simulator-control 0.12.1 `/ues`, mocked backend fixtures (4 UEs), light theme |
| `ue-manager/side-by-side.light.png` | Composite = mockup \| implementation, light |
| `ue-manager/mockup.dark.png` | Mockup, dark |
| `ue-manager/impl.dark.png` | Implementation, dark |
| `ue-manager/side-by-side.dark.png` | Composite, dark |

### Reproduce

```
cd apps/simulator-control
npm install
npm run dev &                     # starts vite on 127.0.0.1:4330
npx playwright test \
  e2e/captures-0.12.1.spec.ts \
  --project=chromium-1440-light \
  --project=chromium-1440-dark
```

Fixtures are mocked inline in `e2e/captures-0.12.1.spec.ts`
(`page.route`), so no live POLARIS backend is required.
