// Filtrage de la liste des analyses (logique pure, testée sous Node).

/** Vues de la liste : toutes, les miennes, favoris, ou un groupe (`group:<id>`). */
export const VIEWS = Object.freeze({ ALL: 'all', MINE: 'mine', FAVORITES: 'favorites' });
const GROUP_PREFIX = 'group:';

export function groupView(groupId) {
  return `${GROUP_PREFIX}${groupId}`;
}

/**
 * @param {object[]} jobs analyses visibles
 * @param {object} filters { view, text, username, favorites: Set<string> }
 */
export function filterJobs(jobs, { view = VIEWS.ALL, text = '', username = null, favorites = new Set() } = {}) {
  const needle = text.trim().toLowerCase();
  return jobs.filter((job) => {
    if (view === VIEWS.MINE && job.requestedBy !== username) return false;
    if (view === VIEWS.FAVORITES && !favorites.has(job.id)) return false;
    if (view.startsWith(GROUP_PREFIX) && job.groupId !== view.slice(GROUP_PREFIX.length)) return false;
    return !needle || `${job.request.target} ${job.label ?? ''} ${job.requestedBy ?? ''}`.toLowerCase().includes(needle);
  });
}

/**
 * Position de chaque analyse en attente dans la file (1 = prochaine à démarrer), par ordre de soumission.
 * @returns {Map<string, number>}
 */
export function queuePositions(jobs) {
  return new Map(jobs.filter((job) => job.status === 'queued')
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
    .map((job, index) => [job.id, index + 1]));
}

/** Deux analyses comparables : terminées avec succès ; la plus ancienne sert de référence. */
export function comparisonOrder(first, second) {
  return new Date(first.createdAt) <= new Date(second.createdAt) ? [first, second] : [second, first];
}

/** Analyses terminées d'une même cible (candidates à la comparaison), la plus récente d'abord. */
export function sameTarget(jobs, job) {
  return jobs.filter((other) => other.id !== job.id && other.status === 'succeeded'
    && other.request.target === job.request.target)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

/** Sous ce nombre d'analyses passées, une "durée habituelle" ne voudrait rien dire. */
const MIN_SAMPLE = 3;

function quantile(sorted, part) {
  const rank = (sorted.length - 1) * part;
  const low = Math.floor(rank);
  const high = Math.ceil(rank);
  return sorted[low] + (sorted[high] - sorted[low]) * (rank - low);
}

/**
 * Durée habituelle d'une analyse, mesurée sur les analyses déjà terminées.
 *
 * Une barre de progression serait un mensonge (on ne sait pas combien de fichiers restent), mais un ordre de
 * grandeur tiré du passé est honnête : d'abord les analyses du même dépôt, sinon toutes. Sous
 * {@link MIN_SAMPLE} mesures, on préfère ne rien annoncer.
 *
 * @param {object[]} jobs analyses connues
 * @param {object} job analyse en cours
 * @returns {{low: number, median: number, high: number, sample: number, sameTarget: boolean} | null} durées en ms
 */
export function durationEstimate(jobs, job) {
  const finished = (jobs ?? []).filter((other) => other.id !== job?.id && other.status === 'succeeded'
    && other.startedAt && other.finishedAt);
  const ofTarget = finished.filter((other) => other.request?.target === job?.request?.target);
  const sample = ofTarget.length >= MIN_SAMPLE ? ofTarget : finished;
  const durations = sample
    .map((other) => new Date(other.finishedAt) - new Date(other.startedAt))
    .filter((duration) => duration > 0)
    .sort((a, b) => a - b);
  if (durations.length < MIN_SAMPLE) return null;
  return {
    low: quantile(durations, 0.25),
    median: quantile(durations, 0.5),
    high: quantile(durations, 0.75),
    sample: durations.length,
    sameTarget: sample === ofTarget,
  };
}

/**
 * État d'un groupe : ce que disent, ensemble, les dernières analyses de chacun de ses dépôts.
 *
 * Chaque analyse prise isolément ne dit rien du parc. On ne garde donc que la dernière analyse réussie par
 * cible (sinon un dépôt analysé dix fois pèserait dix fois), et on compare avec la précédente pour dire qui
 * progresse et qui recule.
 *
 * @param {object[]} jobs analyses du groupe (toutes, y compris non terminées)
 * @returns {{repositories: number, analyses: number, score: number|null, disallowed: number,
 *   deprecated: number, quantumVulnerable: number, vulnerabilities: number, knownExploited: number,
 *   findings: number, lastAnalysisAt: string|null, improved: number, worsened: number,
 *   repositoriesByRisk: object[]}}
 */
export function groupSummary(jobs) {
  const done = (jobs ?? []).filter((job) => job.status === 'succeeded' && job.summary)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const latest = new Map();
  const previous = new Map();
  for (const job of done) {
    const target = job.request?.target ?? job.id;
    if (!latest.has(target)) latest.set(target, job);
    else if (!previous.has(target)) previous.set(target, job);
  }
  const current = [...latest.values()];
  const total = (champ) => current.reduce((somme, job) => somme + (job.summary[champ] ?? 0), 0);
  const parStatut = (statut) => current.reduce((somme, job) => somme + (job.summary.byStatus?.[statut] ?? 0), 0);
  const scores = current.map((job) => job.summary.score).filter((score) => typeof score === 'number');
  const evolution = current.map((job) => {
    const avant = previous.get(job.request?.target ?? job.id);
    return avant ? job.summary.score - avant.summary.score : null;
  }).filter((delta) => delta !== null);

  return {
    repositories: current.length,
    analyses: done.length,
    score: scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null,
    disallowed: parStatut('disallowed'),
    deprecated: parStatut('deprecated'),
    quantumVulnerable: total('quantumVulnerable'),
    vulnerabilities: total('vulnerabilities'),
    knownExploited: total('knownExploited'),
    findings: total('findings'),
    lastAnalysisAt: current.length
      ? current.map((job) => job.finishedAt ?? job.createdAt).sort().at(-1) : null,
    improved: evolution.filter((delta) => delta > 0).length,
    worsened: evolution.filter((delta) => delta < 0).length,
    // Les dépôts à traiter en premier : d'abord les interdits, puis le score le plus bas.
    repositoriesByRisk: current
      .map((job) => ({
        id: job.id,
        target: job.request?.target ?? '-',
        label: job.label ?? null,
        score: job.summary.score,
        disallowed: job.summary.byStatus?.disallowed ?? 0,
        deprecated: job.summary.byStatus?.deprecated ?? 0,
        quantumVulnerable: job.summary.quantumVulnerable ?? 0,
        at: job.finishedAt ?? job.createdAt,
        delta: previous.has(job.request?.target ?? job.id)
          ? job.summary.score - previous.get(job.request?.target ?? job.id).summary.score : null,
      }))
      .sort((a, b) => b.disallowed - a.disallowed || a.score - b.score),
  };
}
