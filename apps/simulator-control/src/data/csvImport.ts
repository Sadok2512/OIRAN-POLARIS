// 0.6.0 — Streaming CSV line counter + per-line parser used by both the
// Provisioning and UE Manager import flows. The browser reads the file
// in 1 MiB chunks and yields to the main thread between chunks so a
// 100 000-line file stays responsive without a Web Worker.
//
// The output is intentionally minimal: we need the line count up-front
// (to tell the operator "YOUR FILE IS TOO BIG" before the POST), and we
// need to surface the first N malformed lines in the preview. The
// authoritative validation runs on the backend; this helper never
// forwards or persists the parsed rows.

export interface CsvPreview {
  totalLines: number;
  headerLine: string | null;
  firstRows: string[];
  columns: number | null;
  parseErrors: { line: number; message: string }[];
  elapsedMs: number;
}

export interface CsvProgress {
  bytesRead: number;
  totalBytes: number;
  linesSoFar: number;
}

const CHUNK_SIZE = 1 << 20; // 1 MiB
const PREVIEW_ROWS = 5;
const MAX_PARSE_ERRORS = 50;

async function readSlice(file: File, start: number, end: number): Promise<string> {
  const blob = file.slice(start, end);
  if (typeof blob.text === 'function') return blob.text();
  // Fallback (older environments): use FileReader.
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.onerror = () => reject(reader.error ?? new Error('FileReader error'));
    reader.readAsText(blob);
  });
}

/**
 * Chunked, non-blocking CSV counter. Honours \n and \r\n endings and
 * handles the last chunk when the file doesn't end on a newline. Does
 * NOT attempt to parse quoted strings — the backend owns full RFC 4180
 * compliance; the UI just needs the line count + a handful of rows for
 * the preview.
 */
export async function previewCsv(
  file: File,
  onProgress?: (progress: CsvProgress) => void,
): Promise<CsvPreview> {
  const startedAt = typeof performance !== 'undefined' ? performance.now() : Date.now();
  let bytesRead = 0;
  let totalLines = 0;
  let carry = '';
  let headerLine: string | null = null;
  const firstRows: string[] = [];
  const parseErrors: CsvPreview['parseErrors'] = [];
  let columns: number | null = null;

  while (bytesRead < file.size) {
    const end = Math.min(file.size, bytesRead + CHUNK_SIZE);
    const chunk = await readSlice(file, bytesRead, end);
    const data = carry + chunk;
    const lines = data.split(/\r?\n/);
    carry = lines.pop() ?? '';
    for (const raw of lines) {
      totalLines += 1;
      if (totalLines === 1) {
        headerLine = raw;
        columns = raw.split(',').length;
      } else if (firstRows.length < PREVIEW_ROWS) {
        firstRows.push(raw);
      }
      if (columns != null && raw.length > 0 && parseErrors.length < MAX_PARSE_ERRORS) {
        const got = raw.split(',').length;
        if (got !== columns) {
          parseErrors.push({
            line: totalLines,
            message: `column count mismatch (expected ${columns}, got ${got})`,
          });
        }
      }
    }
    bytesRead = end;
    onProgress?.({ bytesRead, totalBytes: file.size, linesSoFar: totalLines });
    // Yield to the event loop so the main thread doesn't stall.
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  // Trailing line (no newline at EOF).
  if (carry.length > 0) {
    totalLines += 1;
    if (totalLines === 1) {
      headerLine = carry;
      columns = carry.split(',').length;
    } else if (firstRows.length < PREVIEW_ROWS) {
      firstRows.push(carry);
    }
  }

  const endedAt = typeof performance !== 'undefined' ? performance.now() : Date.now();
  return {
    totalLines,
    headerLine,
    firstRows,
    columns,
    parseErrors,
    elapsedMs: Math.max(0, Math.round(endedAt - startedAt)),
  };
}

/**
 * Backend cap. The LOT fixes it at 100 000 rows for both endpoints.
 * Includes the header row.
 */
export const CSV_IMPORT_MAX_LINES = 100_000;

export function csvRowCountExceedsCap(preview: CsvPreview): boolean {
  return preview.totalLines > CSV_IMPORT_MAX_LINES;
}
