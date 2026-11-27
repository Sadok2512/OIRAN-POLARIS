// LOT C5 (ordres cœur #9 7218858535 et 7222823828) — depuis
// polaris-control-api 0.37.4, un identifiant de scénario qui porte un
// marqueur d'abonné est refusé à l'entrée (`SCENARIO_ID_SUBSCRIBER_MARKER`).
// Règle : un lot qui ajoute un refus prouve qu'aucun client de la maison
// n'envoie la valeur refusée PAR DÉFAUT. Les identifiants générés par le
// client (`newScenarioId`, envoyé par `encodeDefinition` à
// `POST /scenario-definitions`, et la copie de `duplicateScenario`) étaient en
// base 36 : 42 tirages sur 2 000 000 formaient un marqueur (`imsi`, `supi`,
// `imei`, `suci`, `guti`, `tmsi`). Ils doivent rester dans un alphabet qui ne
// peut en former aucun.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { emptyScenario, newScenarioId } from './model';
import { _reset, duplicateScenario, saveScenario } from './store';

const MARKERS = ['imsi', 'supi', 'msisdn', 'imei', 'suci', 'guti', 'tmsi'];
const GENERATED_ID = /^scn-[0-9a-f]+-[0-9a-f]{6}$/;

function assertSafeGeneratedId(id: string) {
  expect(id).toMatch(GENERATED_ID);
  for (const marker of MARKERS) {
    expect(id.toLowerCase()).not.toContain(marker);
  }
}

beforeEach(() => _reset());
afterEach(() => _reset());

describe('identifiants de scénario générés par le client (lot C5)', () => {
  it('newScenarioId ne produit que des caractères hexadécimaux, donc jamais un marqueur', () => {
    for (let draw = 0; draw < 5_000; draw += 1) {
      assertSafeGeneratedId(newScenarioId());
    }
  });

  it('la copie de duplicateScenario suit la même règle', () => {
    const source = saveScenario(emptyScenario('c5'));
    for (let draw = 0; draw < 200; draw += 1) {
      assertSafeGeneratedId(duplicateScenario(source.id)!.id);
    }
  });

  it("l'alphabet hexadécimal ne peut former aucun des marqueurs", () => {
    for (const marker of MARKERS) {
      expect(/^[0-9a-f]+$/.test(marker)).toBe(false);
      expect([...marker].some((letter) => !'0123456789abcdef'.includes(letter))).toBe(true);
    }
  });
});
