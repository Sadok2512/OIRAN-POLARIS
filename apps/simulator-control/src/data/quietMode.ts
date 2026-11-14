// 0.36.5 — « Mode calme » : pendant un lancement et tant qu'un run lancé
// depuis l'UI est actif, le polling de fond (topbar, inventaire UE) est
// suspendu. Raison mesurée par ANR2 (#10 6882271073) : la charge UI portait
// le cgroup API à 22/87 périodes throttled → garde CPU → ue_start refusé.

let quietUntil = 0;

export function enterQuiet(ms: number): void {
  quietUntil = Math.max(quietUntil, Date.now() + ms);
}

export function leaveQuiet(): void {
  quietUntil = 0;
}

export function isQuiet(now: number = Date.now()): boolean {
  return now < quietUntil;
}

/** refetchInterval helper: `false` while quiet, else the given period. */
export function politeInterval(ms: number): () => number | false {
  return () => (isQuiet() ? false : ms);
}
