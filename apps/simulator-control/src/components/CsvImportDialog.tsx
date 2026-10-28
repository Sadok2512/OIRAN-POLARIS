// 0.6.0 — Shared CSV import dialog used by Provisioning and UE Manager.
// Two phases:
//   1. Preview: non-blocking chunked read of the file to count lines +
//      surface the first malformed rows. The operator sees the row count
//      BEFORE the POST, which lets us refuse 100 001+ rows locally
//      (backend caps the import at CSV_IMPORT_MAX_LINES) without a
//      wasted round-trip.
//   2. Upload: single multipart POST, backend answers with a per-line
//      report that we render as a scrollable table.
//
// The parser never streams rows to the network — this is a deliberate
// atomicity choice from the backend contract.

import { useRef, useState } from 'react';
import { AlertTriangle, FileUp, Upload, X } from 'lucide-react';
import {
  CSV_IMPORT_MAX_LINES,
  csvRowCountExceedsCap,
  previewCsv,
  type CsvPreview,
  type CsvProgress,
} from '@/data/csvImport';
import { uploadCsvImport, type CsvImportReport } from '@/data/provisioningApi';
import { ApiError } from '@shared/api';

type Phase = 'idle' | 'previewing' | 'ready' | 'uploading' | 'done' | 'error';

export function CsvImportDialog({
  open,
  onClose,
  onImported,
  target,
  title,
  description,
}: {
  open: boolean;
  onClose: () => void;
  onImported?: (report: CsvImportReport) => void;
  target: 'provisioning' | 'ue-profiles';
  title: string;
  description: string;
}) {
  const [phase, setPhase] = useState<Phase>('idle');
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<CsvPreview | null>(null);
  const [progress, setProgress] = useState<CsvProgress | null>(null);
  const [report, setReport] = useState<CsvImportReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  function reset() {
    setPhase('idle');
    setFile(null);
    setPreview(null);
    setProgress(null);
    setReport(null);
    setError(null);
    if (inputRef.current) inputRef.current.value = '';
  }

  async function handlePick(nextFile: File | undefined) {
    if (!nextFile) return;
    setFile(nextFile);
    setPreview(null);
    setReport(null);
    setError(null);
    setPhase('previewing');
    try {
      const previewed = await previewCsv(nextFile, (p) => setProgress(p));
      setPreview(previewed);
      setPhase('ready');
    } catch (err) {
      setError(`PREVIEW_FAILED · ${(err as Error).message}`);
      setPhase('error');
    }
  }

  async function handleUpload() {
    if (!file || !preview) return;
    if (csvRowCountExceedsCap(preview)) return;
    setPhase('uploading');
    setError(null);
    try {
      const result = await uploadCsvImport(target, file);
      setReport(result);
      setPhase('done');
      onImported?.(result);
    } catch (err) {
      const code = err instanceof ApiError ? err.code : 'CSV_IMPORT_FAILED';
      setError(`${code} · ${(err as Error).message}`);
      setPhase('error');
    }
  }

  if (!open) return null;

  const tooBig = preview && csvRowCountExceedsCap(preview);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="csv-import-title"
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4"
      data-testid="csv-import-dialog"
    >
      <div className="ep-card w-full max-w-2xl p-5 flex flex-col gap-3 my-4">
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileUp width={16} height={16} className="text-primary" />
            <h2 id="csv-import-title" className="text-ep-lg font-semibold">
              {title}
            </h2>
          </div>
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={() => {
              reset();
              onClose();
            }}
            aria-label="Close"
          >
            <X width={13} height={13} />
          </button>
        </header>

        <p className="text-ep-xs text-text-secondary">{description}</p>

        <label className="flex items-center gap-2 text-ep-sm" data-testid="csv-file-input">
          <span className="ep-button ep-button-sm cursor-pointer">
            <Upload width={13} height={13} /> Choose CSV
          </span>
          <input
            ref={inputRef}
            type="file"
            accept=".csv,text/csv"
            onChange={(event) => void handlePick(event.target.files?.[0])}
            className="sr-only"
            data-testid="csv-file-field"
          />
          <span className="text-ep-xs text-text-secondary mono truncate">
            {file ? `${file.name} · ${(file.size / 1024).toFixed(1)} KiB` : 'no file selected'}
          </span>
        </label>

        {phase === 'previewing' && progress && (
          <ProgressBar
            label="Parsing"
            bytesRead={progress.bytesRead}
            totalBytes={progress.totalBytes}
            linesSoFar={progress.linesSoFar}
            testid="csv-preview-progress"
          />
        )}

        {preview && (
          <section
            className="border border-border rounded-md bg-canvas/40 p-3 flex flex-col gap-2"
            data-testid="csv-preview"
          >
            <header className="flex items-center justify-between gap-2 flex-wrap">
              <div>
                <p className="text-ep-xs uppercase tracking-wider text-text-secondary">Preview</p>
                <p className="text-ep-md">
                  <span className="font-semibold">{preview.totalLines.toLocaleString()}</span> lines
                  <span className="text-text-secondary">
                    {' '}
                    · {preview.columns ?? '?'} columns · parsed in {preview.elapsedMs} ms
                  </span>
                </p>
              </div>
              {tooBig ? (
                <span className="ep-badge text-error" data-testid="csv-too-big">
                  OVER CAP · {CSV_IMPORT_MAX_LINES.toLocaleString()} rows max
                </span>
              ) : (
                <span className="ep-badge" data-testid="csv-ok-under-cap">
                  Under cap
                </span>
              )}
            </header>
            {preview.headerLine && (
              <code className="mono text-ep-xs text-text-secondary truncate" data-testid="csv-header-line">
                {preview.headerLine}
              </code>
            )}
            {preview.parseErrors.length > 0 && (
              <div className="text-ep-xs text-warning flex flex-col gap-1" data-testid="csv-parse-errors">
                <p className="flex items-center gap-1">
                  <AlertTriangle width={11} height={11} />
                  {preview.parseErrors.length} local parse issue(s). Full validation runs on the backend.
                </p>
                <ul className="mono">
                  {preview.parseErrors.slice(0, 5).map((e) => (
                    <li key={e.line}>line {e.line}: {e.message}</li>
                  ))}
                </ul>
              </div>
            )}
          </section>
        )}

        {phase === 'uploading' && (
          <p className="text-ep-sm text-text-secondary" data-testid="csv-uploading">
            Uploading to the backend… large files may take several seconds.
          </p>
        )}

        {error && (
          <div
            role="alert"
            className="ep-card border-error/30 p-3 text-ep-sm text-error flex flex-col gap-2"
            data-testid="csv-import-error"
          >
            <p>{error}</p>
          </div>
        )}

        {report && (
          <section
            className="border border-border rounded-md p-3 flex flex-col gap-2"
            data-testid="csv-import-report"
          >
            <header className="flex items-center justify-between gap-2 flex-wrap">
              <div>
                <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
                  Backend report
                </p>
                <p className="text-ep-md">
                  <span className="font-semibold">{report.accepted.toLocaleString()}</span> accepted
                  <span className="text-text-secondary"> · </span>
                  <span className="font-semibold text-error">{report.rejected.toLocaleString()}</span>{' '}
                  rejected
                  <span className="text-text-secondary"> · total {report.total.toLocaleString()}</span>
                </p>
              </div>
            </header>
            {report.errors.length > 0 && (
              <div className="max-h-48 overflow-y-auto border border-border/60 rounded-md">
                <table className="text-ep-xs w-full">
                  <thead className="bg-canvas/60 sticky top-0">
                    <tr>
                      <th className="text-left px-2 py-1">Line</th>
                      <th className="text-left px-2 py-1">Code</th>
                      <th className="text-left px-2 py-1">Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.errors.map((err) => (
                      <tr
                        key={`${err.line}-${err.code}`}
                        data-testid={`csv-import-error-${err.line}`}
                      >
                        <td className="num px-2 py-1">{err.line}</td>
                        <td className="mono px-2 py-1">{err.code}</td>
                        <td className="px-2 py-1">{err.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}

        <footer className="flex items-center justify-end gap-2 pt-2 border-t border-border">
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={() => {
              reset();
              onClose();
            }}
            disabled={phase === 'uploading'}
          >
            Close
          </button>
          <button
            type="button"
            className="ep-button ep-button-sm ep-button-primary"
            onClick={handleUpload}
            disabled={!preview || !!tooBig || phase === 'uploading' || phase === 'done'}
            data-testid="csv-upload-submit"
          >
            {phase === 'uploading' ? 'Uploading…' : phase === 'done' ? 'Done' : 'Upload'}
          </button>
        </footer>
      </div>
    </div>
  );
}

function ProgressBar({
  label,
  bytesRead,
  totalBytes,
  linesSoFar,
  testid,
}: {
  label: string;
  bytesRead: number;
  totalBytes: number;
  linesSoFar: number;
  testid: string;
}) {
  const percent = totalBytes === 0 ? 100 : Math.round((bytesRead / totalBytes) * 100);
  return (
    <div className="flex flex-col gap-1" data-testid={testid}>
      <div className="flex items-center justify-between text-ep-xs text-text-secondary">
        <span>{label}…</span>
        <span className="mono">
          {percent}% · {linesSoFar.toLocaleString()} lines
        </span>
      </div>
      <div className="h-1 bg-canvas rounded-full overflow-hidden">
        <div className="h-full bg-primary" style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}
