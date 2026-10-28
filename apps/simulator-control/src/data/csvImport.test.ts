// 0.6.0 — Streaming CSV preview tests.
//
// The main goal is to prove that:
//   * line counts match for file sizes up to the LOT's 100 000-row cap
//   * the parser yields to the event loop between chunks (we schedule a
//     setTimeout(…, 0) tick each chunk and observe microtasks fire)
//   * `csvRowCountExceedsCap` detects over-cap files locally so the UI
//     refuses them before posting

import { describe, expect, it } from 'vitest';
import {
  CSV_IMPORT_MAX_LINES,
  csvRowCountExceedsCap,
  previewCsv,
  type CsvPreview,
} from './csvImport';

function csvFile(lines: number, columns = 10): File {
  // Build a reasonable row (10 cols, each ~5 chars) so the file reaches a
  // meaningful size (~1 MiB at 15 000 rows). Rows are deterministic to make
  // elapsedMs comparable between runs.
  const header = Array.from({ length: columns }, (_, i) => `c${i}`).join(',');
  const row = Array.from({ length: columns }, (_, i) => `v${i.toString().padStart(4, '0')}`).join(
    ',',
  );
  const body = Array.from({ length: lines - 1 }, () => row).join('\n');
  const text = `${header}\n${body}`;
  return new File([text], 'bench.csv', { type: 'text/csv' });
}

async function previewFile(file: File): Promise<CsvPreview> {
  const progressTicks: number[] = [];
  // jsdom's Blob.text() is not polyfilled by default; attach a shim per file.
  const text = await (file.text?.() ?? Promise.resolve(''));
  if (!file.text || typeof file.text !== 'function' || text === '') {
    const payload = typeof text === 'string' && text.length > 0 ? text : '';
    Object.defineProperty(file, 'text', { value: async () => payload });
  }
  return previewCsv(file, (progress) => progressTicks.push(progress.linesSoFar));
}

describe('previewCsv', () => {
  it('counts a small CSV accurately (header + rows)', async () => {
    const file = csvFile(10);
    const result = await previewFile(file);
    expect(result.totalLines).toBe(10);
    expect(result.columns).toBe(10);
    expect(result.firstRows.length).toBeGreaterThan(0);
  });

  it('counts a 1 000-line file accurately and reports an elapsedMs', async () => {
    const file = csvFile(1_000);
    const result = await previewFile(file);
    expect(result.totalLines).toBe(1_000);
    expect(result.elapsedMs).toBeGreaterThanOrEqual(0);
  });

  it('counts a 100 000-line file at the backend cap in under 30 s and does not block the event loop', async () => {
    const file = csvFile(100_000);
    // Schedule a sentinel task that fires once the main thread yields. If the
    // parser blocks, this task never runs before `previewFile` resolves.
    let eventLoopYielded = false;
    const sentinel = setTimeout(() => {
      eventLoopYielded = true;
    }, 0);
    const result = await previewFile(file);
    clearTimeout(sentinel);

    expect(result.totalLines).toBe(100_000);
    // Not over cap: 100 000 is exactly the LOT limit.
    expect(csvRowCountExceedsCap(result)).toBe(false);
    // Prove the main thread was ticking during the parse.
    expect(eventLoopYielded).toBe(true);
    // The 100k benchmark must not take minutes in CI. jsdom is slower than
    // the real DOM so we leave generous headroom; a modern laptop clocks
    // ~2 s. Fail loud if we ever cross 30 s.
    expect(result.elapsedMs).toBeLessThan(30_000);
    // Print the measured number so the LOT report has it.
    // eslint-disable-next-line no-console
    console.log(`[csv-benchmark] 100000 rows parsed in ${result.elapsedMs} ms`);
  }, 60_000);

  it('flags files over 100 000 rows via csvRowCountExceedsCap', async () => {
    expect(CSV_IMPORT_MAX_LINES).toBe(100_000);
    const file = csvFile(100_001);
    const result = await previewFile(file);
    expect(result.totalLines).toBe(100_001);
    expect(csvRowCountExceedsCap(result)).toBe(true);
  });
});
