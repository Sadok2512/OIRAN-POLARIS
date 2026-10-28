import type { Page } from '@playwright/test';

const configuredProfiles = [1, 2, 3, 4].map(index => ({
  id: `UE-0${index}`,
  pseudonym: `UE-PSEUDONYM-0${index}`,
  profile: `ue-0${index}.yaml`,
  serving_gnb: 'GNB-01',
  simulator: 'UERANSIM',
  state: index === 4 ? 'STOPPED' : 'PDU_ACTIVE',
  configured: true,
  controller_owned: index !== 1,
  ownership: index === 1 ? 'SHARED_PROTECTED' : 'POLARIS_CONTROLLER',
  subscription_status: 'VERIFIED',
  actions: {
    start: index === 4,
    stop: index === 2 || index === 3,
    traffic: index === 2 || index === 3,
    reason: index === 1 ? 'SHARED_UE_PROTECTED' : 'READY',
  },
}));

const items = configuredProfiles.map((profile, offset) => {
  const running = offset < 3;
  return {
    id: profile.pseudonym,
    internal_ue_id: profile.id,
    profile: profile.profile,
    profile_state: 'CONFIGURED',
    subscription_status: 'VERIFIED',
    serving_node: 'GNB-01',
    process_state: running ? 'RUNNING' : 'STOPPED',
    registration_state: running ? 'REGISTERED' : 'DEREGISTERED',
    rrc_state: 'UNKNOWN',
    pdu_session: running ? 'ACTIVE' : 'INACTIVE',
    ue_ip: running ? `10.46.0.${offset + 4}` : null,
    traffic_state: running ? 'IDLE' : 'STOPPED',
    traffic_target_verified: offset === 1 || offset === 2,
    uptime_seconds: running ? 120 : null,
    last_event: null,
    controller_owned: profile.controller_owned,
    ownership: profile.ownership,
    actions: profile.actions,
  };
});

export const knownInventory = {
  items,
  configured_profiles: configuredProfiles,
  configured_count: 4,
  planned_count: 4,
  max_configurable: 10_000,
  active_count: 3,
  registered_count: 3,
  pdu_session_count: 3,
  observed_at_epoch_s: 1_798_000_000,
  cache_version: 7,
  cache_fresh: true,
  source: 'PLAYWRIGHT_KNOWN_INVENTORY_FIXTURE',
};

export async function installInventoryFixture(page: Page): Promise<void> {
  await page.route('**/api/v1/ues', route => route.fulfill({ json: knownInventory }));
}
