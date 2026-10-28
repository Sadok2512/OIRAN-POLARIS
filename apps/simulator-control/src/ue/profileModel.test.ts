import { describe, expect, it } from 'vitest';
import {
  emptyProfile,
  generateBulk,
  parseCsv,
  toCsv,
  validateProfile,
  type UeProfileRecord,
} from './profileModel';

describe('UE profile validation', () => {
  it('requires id, owner and servingGnb', () => {
    const issues = validateProfile(emptyProfile());
    const fields = issues.map((issue) => issue.path);
    expect(fields).toContain('id');
    expect(fields).toContain('owner');
    expect(fields).toContain('servingGnb');
  });

  it('accepts a well-formed draft', () => {
    expect(
      validateProfile({
        id: 'ue-00001',
        owner: 'ops',
        servingGnb: 'gnb-01',
      }),
    ).toHaveLength(0);
  });

  it('rejects IMSI shorter than 14 digits', () => {
    const issues = validateProfile({
      id: 'ue-1',
      owner: 'ops',
      servingGnb: 'gnb-1',
      imsi: '12345',
    });
    expect(issues.find((issue) => issue.path === 'imsi')).toBeTruthy();
  });

  it('rejects a non-IPv4 UE IP', () => {
    const issues = validateProfile({
      id: 'ue-1',
      owner: 'ops',
      servingGnb: 'gnb-1',
      ueIp: 'not-an-ip',
    });
    expect(issues.find((issue) => issue.path === 'ueIp')).toBeTruthy();
  });
});

describe('UE profile CSV round-trip', () => {
  const sample: UeProfileRecord[] = [
    {
      id: 'ue-1',
      owner: 'alice',
      servingGnb: 'gnb-01',
      imsi: '208990000000001',
      plmn: '20899',
      apn: 'internet',
      ueIp: '10.0.0.1',
      notes: 'first, with "comma"',
      createdAt: 1,
      updatedAt: 1,
    },
    {
      id: 'ue-2',
      owner: 'bob',
      servingGnb: 'gnb-02',
      createdAt: 2,
      updatedAt: 2,
    },
  ];

  it('round-trips through CSV preserving commas and quotes', () => {
    const csv = toCsv(sample);
    const parsed = parseCsv(csv);
    expect(parsed.errors).toHaveLength(0);
    expect(parsed.profiles).toHaveLength(2);
    expect(parsed.profiles[0]).toMatchObject({
      id: 'ue-1',
      owner: 'alice',
      servingGnb: 'gnb-01',
      ueIp: '10.0.0.1',
      notes: 'first, with "comma"',
    });
    expect(parsed.profiles[1]).toMatchObject({ id: 'ue-2', owner: 'bob', servingGnb: 'gnb-02' });
  });

  it('reports an invalid row and keeps the valid ones', () => {
    const csv = ['id,owner,servingGnb', 'ue-ok,alice,gnb-01', ',bob,gnb-02'].join('\n');
    const parsed = parseCsv(csv);
    expect(parsed.profiles).toHaveLength(1);
    expect(parsed.errors).toHaveLength(1);
    expect(parsed.errors[0].line).toBe(3);
  });

  it('fails if the header has no id column', () => {
    const parsed = parseCsv('name,owner\nue-1,alice');
    expect(parsed.profiles).toHaveLength(0);
    expect(parsed.errors[0].message).toMatch(/id/);
  });
});

describe('bulk create generator', () => {
  it('produces 10,000 profiles with padded ids', () => {
    const result = generateBulk({
      count: 10_000,
      prefix: 'ue-',
      startIndex: 1,
      padWidth: 5,
      owner: 'ops',
      servingGnb: 'gnb-01',
    });
    expect(result.errors).toHaveLength(0);
    expect(result.profiles).toHaveLength(10_000);
    expect(result.profiles[0].id).toBe('ue-00001');
    expect(result.profiles[9_999].id).toBe('ue-10000');
  });

  it('rejects counts above the hard cap', () => {
    const result = generateBulk({
      count: 10_001,
      prefix: 'ue-',
      startIndex: 1,
      padWidth: 5,
      owner: 'ops',
      servingGnb: 'gnb-01',
    });
    expect(result.profiles).toHaveLength(0);
    expect(result.errors.join(' ')).toMatch(/10,000/);
  });

  it('appends IMSI base + suffix truncated to 15 digits', () => {
    const result = generateBulk({
      count: 2,
      prefix: 'ue-',
      startIndex: 1,
      padWidth: 3,
      owner: 'ops',
      servingGnb: 'gnb-01',
      imsiBase: '208990000000000',
    });
    expect(result.profiles[0].imsi).toHaveLength(15);
    expect(result.profiles[0].imsi?.endsWith('001')).toBe(true);
    expect(result.profiles[1].imsi?.endsWith('002')).toBe(true);
  });
});
