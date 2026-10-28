import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  _resetProfiles,
  _seedProfiles,
  ProfileStoreError,
  bulkCreateProfiles,
  cloneProfile,
  createProfile,
  deleteProfiles,
  listProfiles,
  paginate,
  updateProfile,
} from './profileStore';

beforeEach(() => _resetProfiles());
afterEach(() => _resetProfiles());

describe('UE profile store — CRUD', () => {
  it('creates a profile with createdAt + updatedAt stamps', () => {
    const created = createProfile({ id: 'ue-1', owner: 'alice', servingGnb: 'gnb-01' });
    expect(created.id).toBe('ue-1');
    expect(created.createdAt).toBeGreaterThan(0);
    expect(created.updatedAt).toBe(created.createdAt);
    expect(listProfiles()).toHaveLength(1);
  });

  it('rejects duplicate ids', () => {
    createProfile({ id: 'ue-1', owner: 'a', servingGnb: 'g' });
    expect(() =>
      createProfile({ id: 'ue-1', owner: 'b', servingGnb: 'g' }),
    ).toThrow(ProfileStoreError);
  });

  it('updates a profile without changing createdAt', () => {
    const created = createProfile({ id: 'ue-1', owner: 'a', servingGnb: 'g' });
    const updated = updateProfile('ue-1', {
      id: 'ue-1',
      owner: 'a',
      servingGnb: 'g',
      notes: 'edited',
    });
    expect(updated.createdAt).toBe(created.createdAt);
    expect(updated.updatedAt).toBeGreaterThanOrEqual(created.updatedAt);
    expect(updated.notes).toBe('edited');
  });

  it('rejects renaming to an existing id', () => {
    createProfile({ id: 'ue-1', owner: 'a', servingGnb: 'g' });
    createProfile({ id: 'ue-2', owner: 'b', servingGnb: 'g' });
    expect(() =>
      updateProfile('ue-1', { id: 'ue-2', owner: 'a', servingGnb: 'g' }),
    ).toThrow(ProfileStoreError);
  });

  it('clones a profile and clears UE IP for the new entry', () => {
    createProfile({ id: 'ue-1', owner: 'a', servingGnb: 'g', ueIp: '10.0.0.1', notes: 'n' });
    const copy = cloneProfile('ue-1', 'ue-2');
    expect(copy.id).toBe('ue-2');
    expect(copy.owner).toBe('a');
    expect(copy.ueIp).toBe('');
    expect(copy.notes).toBe('n');
    expect(listProfiles()).toHaveLength(2);
  });

  it('deletes several profiles at once and returns the count', () => {
    createProfile({ id: 'ue-1', owner: 'a', servingGnb: 'g' });
    createProfile({ id: 'ue-2', owner: 'a', servingGnb: 'g' });
    createProfile({ id: 'ue-3', owner: 'a', servingGnb: 'g' });
    expect(deleteProfiles(['ue-1', 'ue-3'])).toBe(2);
    expect(listProfiles().map((profile) => profile.id)).toEqual(['ue-2']);
  });
});

describe('UE profile store — bulk', () => {
  it('creates 10,000 profiles and reports zero skipped on a clean store', () => {
    const drafts = Array.from({ length: 10_000 }, (_, index) => ({
      id: `ue-${(index + 1).toString().padStart(5, '0')}`,
      owner: 'ops',
      servingGnb: 'gnb-01',
    }));
    const result = bulkCreateProfiles(drafts);
    expect(result.created).toBe(10_000);
    expect(result.skipped).toHaveLength(0);
    expect(listProfiles()).toHaveLength(10_000);
  });

  it('skips drafts that collide with existing ids', () => {
    createProfile({ id: 'ue-1', owner: 'a', servingGnb: 'g' });
    const result = bulkCreateProfiles([
      { id: 'ue-1', owner: 'a', servingGnb: 'g' },
      { id: 'ue-2', owner: 'a', servingGnb: 'g' },
    ]);
    expect(result.created).toBe(1);
    expect(result.skipped).toEqual([
      expect.objectContaining({ id: 'ue-1', reason: expect.stringMatching(/exists/) }),
    ]);
  });

  it('caps additions at MAX_PROFILES (10,000)', () => {
    const seed = Array.from({ length: 9_998 }, (_, index) => ({
      id: `ue-${index}`,
      owner: 'a',
      servingGnb: 'g',
      createdAt: 1,
      updatedAt: 1,
    }));
    _seedProfiles(seed);
    const drafts = Array.from({ length: 10 }, (_, index) => ({
      id: `fresh-${index}`,
      owner: 'a',
      servingGnb: 'g',
    }));
    const result = bulkCreateProfiles(drafts);
    expect(result.created).toBe(2);
    expect(result.skipped).toHaveLength(8);
    expect(listProfiles()).toHaveLength(10_000);
  });
});

describe('UE profile store — pagination', () => {
  function seed(count: number) {
    const now = Date.now();
    _seedProfiles(
      Array.from({ length: count }, (_, index) => ({
        id: `ue-${(index + 1).toString().padStart(5, '0')}`,
        owner: index % 2 === 0 ? 'alice' : 'bob',
        servingGnb: `gnb-${(index % 10).toString().padStart(2, '0')}`,
        createdAt: now - index,
        updatedAt: now - index,
      })),
    );
  }

  it('paginates a 10,000-row set in <200 ms per page', () => {
    seed(10_000);
    const started = performance.now();
    const page = paginate(listProfiles(), { page: 1, pageSize: 50 });
    const elapsed = performance.now() - started;
    expect(page.items).toHaveLength(50);
    expect(page.total).toBe(10_000);
    expect(page.pageCount).toBe(200);
    expect(elapsed).toBeLessThan(200);
  });

  it('filters by owner and recomputes pageCount', () => {
    seed(100);
    const page = paginate(listProfiles(), { page: 1, pageSize: 25, owner: 'alice' });
    expect(page.filteredTotal).toBe(50);
    expect(page.pageCount).toBe(2);
    expect(page.items.every((profile) => profile.owner === 'alice')).toBe(true);
  });

  it('clamps page to pageCount when it is out of range', () => {
    seed(10);
    const page = paginate(listProfiles(), { page: 99, pageSize: 5 });
    expect(page.page).toBe(2);
    expect(page.items).toHaveLength(5);
  });

  it('full-text search matches id/owner/servingGnb/imsi/notes', () => {
    seed(20);
    const page = paginate(listProfiles(), {
      page: 1,
      pageSize: 50,
      search: 'ue-00001',
    });
    expect(page.filteredTotal).toBe(1);
    expect(page.items[0].id).toBe('ue-00001');
  });
});
