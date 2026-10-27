import { describe, expect, it } from 'vitest';
import { formatTimestampUtc } from '../utils/time';

describe('UTC timestamp formatting', () => {
  it('formats exact epoch-second captures without exposing raw Unix time', () => {
    expect(formatTimestampUtc('1792872460.866283311Z')).toBe('2026-10-24 20:07:40.866 UTC');
  });

  it('preserves malformed values instead of inventing a time', () => {
    expect(formatTimestampUtc('not-a-timestamp')).toBe('not-a-timestamp');
  });
});
