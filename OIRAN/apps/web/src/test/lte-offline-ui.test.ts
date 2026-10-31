import { describe, expect, it } from 'vitest';
import sessionExplorer from '../pages/SessionExplorer.tsx?raw';
import appShell from '../layouts/AppShell.tsx?raw';
import packetAnalyzer from '../pages/PacketAnalyzer.tsx?raw';

describe('LTE offline Analyzer contract', () => {
  it('keeps LTE visibly synthetic-only and exposes all offline planes', () => {
    expect(sessionExplorer).toContain('LTE · Prepared (synthetic only)');
    expect(appShell).toContain('LTE · Prepared (synthetic only)');
    for (const plane of ['S1-MME', 'S11', 'S1-U']) expect(sessionExplorer).toContain(plane);
  });

  it('exposes the LTE decoder protocols without removing 5G protocols', () => {
    for (const protocol of ['S1AP', 'NAS-EPS-MM', 'NAS-EPS-SM', 'GTPv2-C', 'GTP-U']) {
      expect(packetAnalyzer).toContain(protocol);
    }
    for (const protocol of ['NGAP', 'NAS-5GMM', 'NAS-5GSM', 'PFCP']) {
      expect(packetAnalyzer).toContain(protocol);
    }
  });
});
