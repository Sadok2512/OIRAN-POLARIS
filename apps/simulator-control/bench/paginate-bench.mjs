// Standalone bench of paginate() at 10 000 profiles. Mirrors
// `src/ue/profileStore.paginate` semantics: haystack join + lowercase
// + filter + sort + slice. The measurement isolates the CPU cost of
// the filter chain from React/vitest overhead.
const now = Date.now();
const profiles = Array.from({ length: 10_000 }, (_, i) => ({
  id: `ue-${(i + 1).toString().padStart(5, '0')}`,
  owner: i % 2 === 0 ? 'alice' : 'bob',
  servingGnb: `gnb-${(i % 10).toString().padStart(2, '0')}`,
  imsi: `imsi-00101000000${(i % 1000).toString().padStart(4, '0')}`,
  ueIp: `10.46.${i >> 8}.${i & 0xff}`,
  notes: '',
  createdAt: now - i,
  updatedAt: now - i,
}));

function paginate(profiles, options) {
  const total = profiles.length;
  const needle = (options.search ?? '').trim().toLowerCase();
  const ownerFilter = (options.owner ?? '').trim().toLowerCase();
  const gnbFilter = (options.servingGnb ?? '').trim().toLowerCase();
  let filtered = profiles;
  if (needle || ownerFilter || gnbFilter) {
    filtered = profiles.filter((p) => {
      if (needle) {
        const hay = [
          p.id, p.owner, p.servingGnb,
          options.includeImsi ? p.imsi ?? '' : '',
          p.ueIp ?? '', p.notes ?? '',
        ].join(' ').toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      if (ownerFilter && p.owner.toLowerCase() !== ownerFilter) return false;
      if (gnbFilter && p.servingGnb.toLowerCase() !== gnbFilter) return false;
      return true;
    });
  }
  const sorted = [...filtered].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const pageSize = options.pageSize ?? 50;
  const start = ((options.page ?? 1) - 1) * pageSize;
  return { items: sorted.slice(start, start + pageSize), total, filteredTotal: sorted.length };
}

// Warm up V8.
for (let i = 0; i < 3; i++) paginate(profiles, { search: 'ue-00042', page: 1, pageSize: 50, includeImsi: true });

const runs = [];
for (let i = 0; i < 20; i++) {
  const t = performance.now();
  const r = paginate(profiles, { search: 'ue-00042', page: 1, pageSize: 50, includeImsi: true });
  const dt = performance.now() - t;
  runs.push({ dt, matches: r.filteredTotal });
}
runs.sort((a, b) => a.dt - b.dt);
const med = runs[Math.floor(runs.length / 2)];
const max = runs[runs.length - 1];
console.log(`median=${med.dt.toFixed(2)}ms max=${max.dt.toFixed(2)}ms matches=${med.matches}`);

const runsEmpty = [];
for (let i = 0; i < 20; i++) {
  const t = performance.now();
  paginate(profiles, { search: '', page: 1, pageSize: 50, includeImsi: true });
  runsEmpty.push(performance.now() - t);
}
runsEmpty.sort((a, b) => a - b);
console.log(`no-filter median=${runsEmpty[10].toFixed(2)}ms max=${runsEmpty[19].toFixed(2)}ms`);
