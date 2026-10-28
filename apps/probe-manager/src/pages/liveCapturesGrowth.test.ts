import { describe, expect, it } from 'vitest';
import { computeGrowth, isStalled, readSize } from './LiveCaptures';
import type { Capture } from '@shared/types';

function cap(partial: Partial<Capture>): Capture {
  return { capture_id: 'id', name: 'n', ...partial } as Capture;
}

describe('readSize', () => {
  it('returns null when both size_bytes and metrics.storage_bytes are missing', () => {
    expect(readSize(cap({}))).toBeNull();
  });

  it('reads size_bytes first, metrics.storage_bytes as fallback', () => {
    expect(readSize(cap({ size_bytes: 42 }))).toBe(42);
    expect(readSize(cap({ metrics: { storage_bytes: 7 } } as unknown as Partial<Capture>))).toBe(7);
  });

  it('surfaces 0 bytes honestly (0 ≠ unknown)', () => {
    expect(readSize(cap({ size_bytes: 0 }))).toBe(0);
  });
});

describe('computeGrowth', () => {
  it('returns bytes=null before the window is full', () => {
    const start = 1_000;
    expect(computeGrowth([])).toEqual({ bytes: null, windowMs: 0, sizeKnown: false });
    expect(computeGrowth([{ timestamp: start, size: 100 }])).toEqual({
      bytes: null,
      windowMs: 0,
      sizeKnown: true,
    });
    expect(
      computeGrowth([
        { timestamp: start, size: 100 },
        { timestamp: start + 4_000, size: 150 },
      ]),
    ).toEqual({ bytes: null, windowMs: 4_000, sizeKnown: true });
  });

  it('returns the delta once the window reaches 10 s', () => {
    const start = 1_000;
    const result = computeGrowth([
      { timestamp: start, size: 100 },
      { timestamp: start + 10_000, size: 500 },
    ]);
    expect(result).toEqual({ bytes: 400, windowMs: 10_000, sizeKnown: true });
  });

  it('reports sizeKnown=false when every sample has a null size', () => {
    const result = computeGrowth([
      { timestamp: 0, size: null },
      { timestamp: 11_000, size: null },
    ]);
    expect(result).toEqual({ bytes: null, windowMs: 0, sizeKnown: false });
  });

  it('ignores null samples but keeps the real ones for the window', () => {
    const result = computeGrowth([
      { timestamp: 0, size: null },
      { timestamp: 1_000, size: 100 },
      { timestamp: 11_000, size: 100 },
    ]);
    // Non-null samples span 10 s with no growth → bytes 0.
    expect(result).toEqual({ bytes: 0, windowMs: 10_000, sizeKnown: true });
  });
});

describe('isStalled', () => {
  it('is false while the window is still measuring (bytes=null)', () => {
    expect(isStalled('CAPTURING', { bytes: null, windowMs: 4_000, sizeKnown: true })).toBe(false);
  });

  it('is false when the backend never reported a size', () => {
    expect(isStalled('CAPTURING', { bytes: null, windowMs: 0, sizeKnown: false })).toBe(false);
  });

  it('is true once we have a 10 s window with 0 B growth', () => {
    expect(isStalled('CAPTURING', { bytes: 0, windowMs: 10_000, sizeKnown: true })).toBe(true);
  });

  it('is false when 0 B of growth is reported over less than 10 s', () => {
    expect(isStalled('CAPTURING', { bytes: 0, windowMs: 9_999, sizeKnown: true })).toBe(false);
  });

  it('is true for STARTING / STOPPING even without a window', () => {
    expect(isStalled('STARTING', { bytes: null, windowMs: 0, sizeKnown: true })).toBe(true);
    expect(isStalled('STOPPING', { bytes: 100, windowMs: 10_000, sizeKnown: true })).toBe(true);
  });

  it('is false when the capture has growth within the window', () => {
    expect(isStalled('CAPTURING', { bytes: 500, windowMs: 10_000, sizeKnown: true })).toBe(false);
  });
});
