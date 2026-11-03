// Tri et filtrage du catalogue d'algorithmes (logique pure, testée sous Node).

import { STATUSES } from './labels.js';

/** Colonnes triables : clé -> fonction de comparaison ascendante. */
const COMPARATORS = Object.freeze({
  name: (a, b) => a.name.localeCompare(b.name, 'fr'),
  primitive: (a, b) => a.primitive.localeCompare(b.primitive) || a.name.localeCompare(b.name, 'fr'),
  status: (a, b) => statusRank(a.status) - statusRank(b.status) || a.name.localeCompare(b.name, 'fr'),
  quantum: (a, b) => QUANTUM_ORDER.indexOf(quantumPosture(a).id) - QUANTUM_ORDER.indexOf(quantumPosture(b).id)
    || a.name.localeCompare(b.name, 'fr'),
  oid: (a, b) => compareOids(primaryOid(a), primaryOid(b)) || a.name.localeCompare(b.name, 'fr'),
  validity: (a, b) => (a.disallowedAfter ?? Infinity) - (b.disallowedAfter ?? Infinity)
    || a.name.localeCompare(b.name, 'fr'),
});

export const SORT_KEYS = Object.freeze(Object.keys(COMPARATORS));

function statusRank(status) {
  const index = STATUSES.findIndex((s) => s.id === status);
  return index < 0 ? STATUSES.length : index;
}

function primaryOid(algorithm) {
  return algorithm.oids?.[0]?.oid ?? null;
}

/** Compare deux OID arc par arc (numériquement) ; les entrées sans OID vont à la fin. */
export function compareOids(a, b) {
  if (a === b) return 0;
  if (!a) return 1;
  if (!b) return -1;
  const left = a.split('.').map(Number);
  const right = b.split('.').map(Number);
  for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
    const diff = (left[i] ?? -1) - (right[i] ?? -1);
    if (diff !== 0) return diff;
  }
  return 0;
}

export function sortCatalog(algorithms, key = 'primitive', direction = 'asc') {
  const compare = COMPARATORS[key] ?? COMPARATORS.primitive;
  const sign = direction === 'desc' ? -1 : 1;
  return [...algorithms].sort((a, b) => sign * compare(a, b));
}

/** Familles asymétriques : sans vulnérabilité à Shor, elles sont post-quantiques par construction. */
const ASYMMETRIC = new Set(['kem', 'signature', 'key-agree', 'pke']);
/** Familles symétriques et empreintes : Shor ne s'y applique pas, Grover divise la sécurité par deux. */
const SYMMETRIC = new Set(['block-cipher', 'stream-cipher', 'ae', 'hash', 'mac', 'kdf', 'drbg', 'xof']);

/**
 * Position d'une entrée face à un ordinateur quantique. Un simple "vulnérable / résistant" induisait en
 * erreur : DES n'est pas menacé par Shor mais reste à proscrire, et "JWT alg=none" n'est pas une protection.
 *
 * @returns {{ id: string, label: string, hint: string, tone: string }}
 */
export function quantumPosture(algorithm) {
  if (algorithm?.status === 'disallowed') {
    return { id: 'obsolete', label: 'sans objet', tone: 'muted',
      hint: 'Déjà à proscrire aujourd\'hui, indépendamment de la menace quantique.' };
  }
  if (algorithm?.quantumVulnerable) {
    return { id: 'shor', label: 'cassé par Shor', tone: 'serious',
      hint: 'Un ordinateur quantique suffisant casse cette cryptographie : prévoir le remplacement.' };
  }
  if (ASYMMETRIC.has(algorithm?.primitive)) {
    return { id: 'pqc', label: 'résistant (post-quantique)', tone: 'good',
      hint: 'Conçu pour résister à un ordinateur quantique.' };
  }
  if (SYMMETRIC.has(algorithm?.primitive)) {
    return { id: 'grover', label: 'marge réduite (Grover)', tone: 'neutral',
      hint: 'Shor ne s\'applique pas ; Grover divise la sécurité par deux : viser 256 bits de clé '
        + 'et 384 bits d\'empreinte.' };
  }
  return { id: 'depends', label: 'selon les algorithmes employés', tone: 'muted',
    hint: 'Protocole ou entrée générique : la résistance dépend des algorithmes réellement négociés.' };
}

/**
 * @param {object} filters { text, status, primitive, quantum: '' | 'vulnerable' | 'safe' }
 */
/**
 * @param {object} filters { text (nom, alias, OID, note), status, primitive, quantum, type (algorithm | protocol) }
 */
export function filterCatalog(algorithms, { text = '', status = '', primitive = '', quantum = '', type = '' } = {}) {
  const needle = text.trim().toLowerCase();
  return algorithms.filter((a) => (!status || a.status === status)
    && (!primitive || a.primitive === primitive)
    && (!quantum || quantumPosture(a).id === quantum)
    && (!type || (a.assetType ?? 'algorithm') === type)
    && (!needle || [a.id, a.name, ...(a.aliases ?? []), ...(a.tokens ?? []), ...(a.oids ?? []).map((o) => o.oid),
      a.note ?? '', a.recommendation ?? ''].join(' ').toLowerCase().includes(needle)));
}

/** Registre public des OID : fiche d'un OID (description, organisme, sous-arborescence). */
export function oidInfoUrl(oid) {
  return `https://oid-base.com/get/${encodeURIComponent(oid)}`;
}

const compact = (value) => String(value ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');

/**
 * OID officiels à proposer pendant la saisie d'une entrée : même identifiant, sinon nom ou alias reconnu dans le
 * catalogue de référence. Une seule entrée de référence doit correspondre (pas de proposition ambiguë).
 * @param {object[]} reference [{ id, name, aliases, oids }]
 * @param {object} entry { id, name, aliases: string[] }
 * @returns {{ source: object, oids: object[] } | null}
 */
export function suggestOids(reference, { id = '', name = '', aliases = [] } = {}) {
  const byId = reference.find((r) => r.id === id.trim());
  if (byId) return { source: byId, oids: byId.oids };
  const keys = new Set([compact(name), ...aliases.map(compact)].filter((k) => k.length >= 2));
  if (!keys.size) return null;
  const matches = reference.filter((r) => keys.has(compact(r.name)) || keys.has(compact(r.id))
    || r.aliases.some((alias) => keys.has(alias)));
  return matches.length === 1 ? { source: matches[0], oids: matches[0].oids } : null;
}

/** Nombre d'exemples cités dans le résumé d'un import : de quoi reconnaître, sans noyer. */
const DIFF_SAMPLE = 5;

/**
 * Écarts entre le catalogue en place et celui que l'on s'apprête à importer.
 *
 * Remplacer un catalogue à l'aveugle est le meilleur moyen de perdre des entrées ajoutées localement :
 * mieux vaut annoncer ce qui change avant d'écraser.
 *
 * @returns {{added: string[], removed: string[], changed: string[], identical: boolean}}
 */
export function catalogDiff(current, imported) {
  const key = (entry) => JSON.stringify(entry);
  const currentById = new Map((current?.algorithms ?? []).map((a) => [a.id, a]));
  const importedById = new Map((imported?.algorithms ?? []).map((a) => [a.id, a]));
  const added = [...importedById.keys()].filter((id) => !currentById.has(id));
  const removed = [...currentById.keys()].filter((id) => !importedById.has(id));
  const changed = [...importedById.entries()]
    .filter(([id, entry]) => currentById.has(id) && key(currentById.get(id)) !== key(entry))
    .map(([id]) => id);
  return { added, removed, changed, identical: !added.length && !removed.length && !changed.length };
}

/** Résumé lisible des écarts, pour la demande de confirmation avant import. */
export function describeDiff(diff, limit = DIFF_SAMPLE) {
  const partie = (liste, singulier, pluriel) => (liste.length
    ? `${liste.length} ${liste.length > 1 ? pluriel : singulier} : ${liste.slice(0, limit).join(', ')}`
      + `${liste.length > limit ? '...' : ''}`
    : null);
  return [
    partie(diff.added, 'ajout', 'ajouts'),
    partie(diff.removed, 'suppression', 'suppressions'),
    partie(diff.changed, 'modification', 'modifications'),
  ].filter(Boolean);
}

/** Politique attachée à un catalogue, en une phrase. */
export function describePolicy(policy) {
  if (!policy) return null;
  return `Politique "${policy.name}" version ${policy.version}`
    + (policy.publishedBy ? `, publiée par ${policy.publishedBy}` : '')
    + (policy.fingerprint ? ` - empreinte ${policy.fingerprint}` : '');
}
