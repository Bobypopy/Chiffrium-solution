// Logique d'exploitation du rapport : filtres, tris, agrégats. Aucune dépendance au DOM.

import { quantumPosture } from './catalog.js';
import { SEVERITIES, STATUSES } from './labels.js';

const STATUS_ORDER = STATUSES.map((s) => s.id);

export function statusOf(asset) {
  return asset?.verdict?.status ?? 'unknown';
}

export function severityRank(asset) {
  return SEVERITIES.indexOf(asset?.verdict?.severity ?? 'none');
}

/** Tri par défaut : les actifs les plus graves d'abord, puis par nom. */
export function sortAssets(assets, key = 'risk') {
  const copy = [...assets];
  const byName = (a, b) => String(a.name).localeCompare(String(b.name), 'fr');
  const comparators = {
    risk: (a, b) => severityRank(b) - severityRank(a)
      || STATUS_ORDER.indexOf(statusOf(b)) - STATUS_ORDER.indexOf(statusOf(a)) || byName(a, b),
    name: byName,
    occurrences: (a, b) => (b.occurrences?.length ?? 0) - (a.occurrences?.length ?? 0) || byName(a, b),
  };
  return copy.sort(comparators[key] ?? comparators.risk);
}

/**
 * @param {object} filters { text, status, primitive, language, quantumOnly }
 */
export function filterAssets(assets, filters = {}) {
  const text = (filters.text ?? '').trim().toLowerCase();
  return assets.filter((asset) => {
    if (filters.status && statusOf(asset) !== filters.status) return false;
    if (filters.primitive && asset.algorithm?.primitive !== filters.primitive) return false;
    if (filters.language && !(asset.occurrences ?? []).some((o) => o.language === filters.language)) return false;
    if (filters.quantumOnly && !asset.verdict?.quantumVulnerable) return false;
    if (filters.origin && !(asset.occurrences ?? [])
      .some((o) => originOf(o.file, filters.modules) === filters.origin)) return false;
    if (!text) return true;
    const haystack = [asset.name, asset.bomRef, asset.algorithm?.rawName,
      ...(asset.occurrences ?? []).map((o) => `${o.file} ${o.function ?? ''}`)]
      .join(' ').toLowerCase();
    return haystack.includes(text);
  });
}

/** Valeurs distinctes présentes dans le rapport, pour alimenter les listes de filtres. */
export function facets(assets) {
  const primitives = new Set();
  const languages = new Set();
  for (const asset of assets) {
    if (asset.algorithm?.primitive) primitives.add(asset.algorithm.primitive);
    for (const occurrence of asset.occurrences ?? []) {
      if (occurrence.language) languages.add(occurrence.language);
    }
  }
  return { primitives: [...primitives].sort(), languages: [...languages].sort() };
}

/** Répartition ordonnée pour les barres du tableau de bord : [{ key, count, share }]. */
export function distribution(counts = {}, order = null) {
  const keys = order ?? Object.keys(counts).sort((a, b) => (counts[b] ?? 0) - (counts[a] ?? 0));
  const total = Object.values(counts).reduce((sum, n) => sum + n, 0);
  return keys
    .filter((key) => (counts[key] ?? 0) > 0)
    .map((key) => ({ key, count: counts[key], share: total === 0 ? 0 : counts[key] / total }));
}

export function statusDistribution(summary) {
  return distribution(summary?.byStatus ?? {}, STATUS_ORDER);
}

/**
 * Position d'un actif face à un ordinateur quantique, avec les mêmes libellés que le catalogue : cassé par Shor,
 * résistant (post-quantique), marge réduite (Grover)... Null pour un algorithme que le catalogue ne connaît pas.
 */
export function assetQuantumPosture(asset) {
  const verdict = asset?.verdict;
  if (!verdict?.quantumVulnerable && !asset?.algorithm?.catalogId) return null;
  return quantumPosture({ status: verdict?.status, quantumVulnerable: verdict?.quantumVulnerable,
    primitive: asset.algorithm?.primitive });
}

/** Échanges de clés : à migrer en premier (données enregistrées aujourd'hui, déchiffrées demain). */
const KEY_EXCHANGE = new Set(['pke', 'key-agree', 'kem']);

/**
 * Plan de migration post-quantique : chaque actif cassé par Shor, son remplaçant et son étendue. Les échanges
 * de clés passent devant les signatures ("récolter maintenant, déchiffrer plus tard"), puis les plus répandus.
 *
 * @returns {{ asset: object, keyExchange: boolean, files: number }[]}
 */
export function migrationPlan(assets = []) {
  return assets.filter((asset) => asset.verdict?.quantumVulnerable)
    .map((asset) => ({ asset, keyExchange: KEY_EXCHANGE.has(asset.algorithm?.primitive),
      files: new Set((asset.occurrences ?? []).map((o) => o.file)).size }))
    .sort((a, b) => Number(b.keyExchange) - Number(a.keyExchange)
      || (b.asset.occurrences?.length ?? 0) - (a.asset.occurrences?.length ?? 0)
      || String(a.asset.name).localeCompare(String(b.asset.name), 'fr'));
}

/** Actifs à traiter en priorité (interdits puis dépréciés), limités à `limit`. */
export function priorities(assets, limit) {
  return sortAssets(assets.filter((a) => ['disallowed', 'deprecated'].includes(statusOf(a))), 'risk')
    .slice(0, limit);
}

/** Dossiers où l'on trouve du code tiers recopié plutôt que le code du projet. */
const VENDOR_DIRS = ['node_modules', 'vendor', 'third_party', 'thirdparty', 'external', 'externals', 'site-packages',
  '.venv', 'venv', 'bower_components', 'packages', 'dist-packages', '.gradle', '.m2'];
/** Dossiers de test : un algorithme faible y est souvent volontaire (vecteurs de test). */
const TEST_DIRS = ['test', 'tests', 'testing', 'spec', 'specs', '__tests__', 'testdata', 'test-data', 'fixtures',
  'selftest', 'test-fixtures', 'test_fixtures', 'test-vectors', 'test_vectors', 'fuzz', 'fuzzing', 'molecule'];
/**
 * Fichiers de test, mêmes conventions que l'analyse (FooTest.java, x_test.go, a.spec.ts, test_x.py,
 * config_test_helpers.go) : leurs constats y sont déjà abaissés.
 */
const TEST_FILE = /^test_.+\.py$|^tests?\.[a-z0-9]+$|[._-](test|spec)s?\.[a-z0-9]+$|[._-]tests?[._-]|[a-z0-9]Tests?\.[A-Za-z]+$/;

export const ORIGINS = Object.freeze({
  project: { label: 'code du projet', hint: 'Fichier du dépôt analysé : à corriger chez vous.' },
  dependency: { label: 'dépendance embarquée', hint: 'Code tiers recopié dans le dépôt (node_modules, vendor...) : '
    + 'à mettre à jour plutôt qu\'à modifier.' },
  submodule: { label: 'sous-module Git', hint: 'Dépôt Git imbriqué, cloné avec le projet : appartient souvent à '
    + 'une autre équipe.' },
  test: { label: 'code de test', hint: 'Fichier de test : la cryptographie faible y est souvent volontaire '
    + '(vecteurs de test).' },
});

/**
 * Origine d'un fichier du rapport.
 * @param {string} file chemin relatif tel que rapporté
 * @param {object[]} [modules] modules du rapport (`source.modules`), pour reconnaître les sous-modules Git
 * @returns {'project' | 'dependency' | 'submodule' | 'test'}
 */
export function originOf(file, modules = []) {
  const parts = String(file ?? '').split(/[\\/]+/).filter(Boolean);
  const lower = parts.map((part) => part.toLowerCase());
  if (lower.some((part) => VENDOR_DIRS.includes(part))) return 'dependency';
  const submodules = (modules ?? [])
    .filter((m) => m.gitRepository && m.path && m.path !== '.' && m.path !== '')
    .map((m) => String(m.path).replace(/^\.\//, '').toLowerCase());
  const path = lower.join('/');
  if (submodules.some((prefix) => path === prefix || path.startsWith(`${prefix}/`))) return 'submodule';
  const directories = lower.slice(0, -1);
  if (directories.some((part) => TEST_DIRS.includes(part) || part.endsWith('vectors'))) return 'test';
  if (TEST_FILE.test(parts.at(-1) ?? '')) return 'test';
  return 'project';
}

/** Groupement des occurrences d'un actif par fichier : [{ file, occurrences }]. */
export function occurrencesByFile(asset) {
  const groups = new Map();
  for (const occurrence of asset?.occurrences ?? []) {
    const key = occurrence.file ?? '-';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(occurrence);
  }
  return [...groups.entries()].map(([file, occurrences]) => ({
    file,
    occurrences: occurrences.sort((a, b) => (a.line ?? 0) - (b.line ?? 0)),
  }));
}

/** Seuils du score (identiques côté serveur : poids documentés dans SummaryCalculator). */
export const SCORE_THRESHOLDS = Object.freeze({ good: 80, warning: 60 });

export function scoreTone(score) {
  if (score >= SCORE_THRESHOLDS.good) return 'good';
  if (score >= SCORE_THRESHOLDS.warning) return 'warning';
  return 'critical';
}

/** Poids par statut, identiques à ceux de SummaryCalculator côté serveur. */
const SCORE_WEIGHTS = Object.freeze({
  recommended: 1, acceptable: 0.85, 'acceptable-quantum': 0.7, unknown: 0.5, deprecated: 0.25, disallowed: 0,
});

/** Groupe de score d'un actif : les acceptables vulnérables au quantique comptent à part, comme sur le serveur. */
function scoreGroup(asset) {
  const status = statusOf(asset);
  return status === 'acceptable' && asset?.verdict?.quantumVulnerable ? 'acceptable-quantum' : status;
}

/**
 * Décomposition du score : combien de points chaque famille d'actifs coûte, du plus lourd au plus léger.
 *
 * Le score est une moyenne : un actif interdit coûte `100 / nombre d'actifs` points. Savoir que "3 actifs
 * interdits coûtent 28 points" dit quoi corriger en premier, là où le score seul ne dit rien.
 *
 * @returns {{key: string, status: string, quantum: boolean, count: number, points: number,
 *   algorithms: {name: string, count: number}[]}[]}
 */
export function scoreBreakdown(assets, { limit = 4, algorithms = 3 } = {}) {
  if (!assets?.length) return [];
  const groups = new Map();
  for (const asset of assets) {
    const key = scoreGroup(asset);
    const weight = SCORE_WEIGHTS[key] ?? SCORE_WEIGHTS.unknown;
    const lost = ((1 - weight) * 100) / assets.length;
    if (lost <= 0) continue;
    const group = groups.get(key)
      ?? { key, status: key === 'acceptable-quantum' ? 'acceptable' : key,
        quantum: key === 'acceptable-quantum', count: 0, lost: 0, names: new Map() };
    group.count += 1;
    group.lost += lost;
    const name = asset.algorithm?.displayName ?? asset.algorithm?.rawName ?? asset.name ?? '-';
    group.names.set(name, (group.names.get(name) ?? 0) + 1);
    groups.set(key, group);
  }
  return [...groups.values()]
    // Sous un demi-point, l'affichage annoncerait "-0 pt" : autant ne rien dire.
    .filter((group) => group.lost >= 0.5)
    .sort((a, b) => b.lost - a.lost)
    .slice(0, limit)
    .map(({ names, lost, ...group }) => ({
      ...group,
      points: Math.round(lost),
      algorithms: [...names.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0]), 'fr'))
        .slice(0, algorithms).map(([name, count]) => ({ name, count })),
    }));
}
