// Conversion du graphe du rapport vers le format vis-network. Pur : testable sans navigateur.

import { statusOf } from './report.js';

/** Apparence par nature de nœud ; les couleurs sont lues dans les variables CSS au rendu. */
export const NODE_STYLES = Object.freeze({
  function: { shape: 'box', token: '--graph-function' },
  crypto_api: { shape: 'ellipse', token: '--graph-api' },
  file: { shape: 'database', token: '--graph-file' },
  asset: { shape: 'diamond', token: null },
});

export const EDGE_LABELS = Object.freeze({
  calls: 'appelle', uses: 'utilise', produces: 'écrit', consumes: 'lu par',
});

const STATUS_TOKENS = Object.freeze({
  recommended: '--status-good',
  acceptable: '--status-neutral',
  unknown: '--status-muted',
  deprecated: '--status-serious',
  disallowed: '--status-critical',
});

/** Au-delà, le navigateur ne peut plus disposer le graphe confortablement : vue partielle. */
export const DISPLAY_LIMIT = 400;
/** Voisinage embarqué avec un nœud que la vue doit contenir (nombre de liens). */
export const INCLUDE_DEPTH = 2;
const RISK_ORDER = ['disallowed', 'deprecated', 'unknown', 'acceptable', 'recommended'];

/**
 * Modèle du graphe entier : chercher un nœud ne doit pas amputer le graphe, sans quoi on ne voit plus à quoi
 * il est relié. Seule la taille limite la vue, et `include` garantit alors la présence de ce que l'on vient
 * chercher.
 *
 * @param {object} report rapport complet
 * @param {object} options { hideApis, limit: nombre maximal de nœuds affichés,
 *        include: nœuds qui doivent figurer dans une vue partielle }
 * @returns {{nodes: object[], edges: object[], total: number, partial: boolean}} description indépendante de la
 *          bibliothèque de rendu ; `partial` si seule une partie du graphe est montrée
 */
export function toGraphModel(report, options = {}) {
  const graph = report?.callGraph ?? { nodes: [], edges: [] };
  const assetsByRef = new Map((report?.assets ?? []).map((a) => [a.bomRef, a]));
  const hidden = new Set(options.hideApis
    ? graph.nodes.filter((n) => n.kind === 'crypto_api').map((n) => n.id) : []);
  const limit = options.limit ?? DISPLAY_LIMIT;

  let nodes = graph.nodes.filter((n) => !hidden.has(n.id));
  let edges = graph.edges.filter((e) => !hidden.has(e.from) && !hidden.has(e.to));
  const total = nodes.length;

  let keep = null;
  if (nodes.length > limit) {
    // Vue partielle : ce que l'on vient chercher passe en premier, avec son voisinage immédiat ; le reste de
    // la place va aux actifs les plus risqués et à leurs voisins.
    const present = new Set(nodes.map((n) => n.id));
    const include = (options.include ?? []).filter((id) => present.has(id));
    keep = new Set();
    if (include.length) {
      for (const id of neighbourhood(include, edges, INCLUDE_DEPTH, limit)) keep.add(id);
    }
    const risk = (node) => {
      const asset = node.assetRef ? assetsByRef.get(node.assetRef) : null;
      const index = asset ? RISK_ORDER.indexOf(statusOf(asset)) : -1;
      return index < 0 ? RISK_ORDER.length : index;
    };
    const seeds = nodes.filter((n) => n.kind === 'asset').sort((a, b) => risk(a) - risk(b)).map((n) => n.id);
    for (const seed of seeds) {
      if (keep.size >= limit) break;
      if (keep.has(seed)) continue;
      for (const id of neighbourhood(seed, edges, Infinity, limit - keep.size)) keep.add(id);
    }
  }
  if (keep) {
    nodes = nodes.filter((n) => keep.has(n.id));
    edges = edges.filter((e) => keep.has(e.from) && keep.has(e.to));
  }

  return {
    total,
    partial: nodes.length < total,
    nodes: nodes.map((node) => {
      const style = NODE_STYLES[node.kind] ?? NODE_STYLES.function;
      const asset = node.assetRef ? assetsByRef.get(node.assetRef) : null;
      return {
        id: node.id,
        label: node.label,
        kind: node.kind,
        shape: style.shape,
        colorToken: asset ? STATUS_TOKENS[statusOf(asset)] : style.token,
        title: [node.label, node.file ? `${node.file}${node.line ? `:${node.line}` : ''}` : null]
          .filter(Boolean).join('\n'),
        assetRef: node.assetRef ?? null,
      };
    }),
    edges: edges.map((edge) => ({
      id: `${edge.from}->${edge.to}`,
      from: edge.from,
      to: edge.to,
      label: EDGE_LABELS[edge.kind] ?? edge.kind,
      kind: edge.kind,
      dashed: edge.kind === 'calls',
    })),
  };
}

/** Nature d'un nœud, dite en toutes lettres : le graphe doit aussi se lire sans le voir. */
export const NODE_KIND_LABELS = Object.freeze({
  function: 'fonction',
  crypto_api: 'appel cryptographique',
  file: 'fichier de clé',
  asset: 'actif cryptographique',
});

/** Ordre de parcours au clavier : les actifs d'abord (ce que l'on vient chercher), puis le reste par nom. */
export function keyboardOrder(model) {
  const rank = (node) => (node.kind === 'asset' ? 0 : node.kind === 'crypto_api' ? 1 : 2);
  return [...(model?.nodes ?? [])]
    .sort((a, b) => rank(a) - rank(b) || String(a.label).localeCompare(String(b.label), 'fr'));
}

/**
 * Voisins directs d'un nœud, avec le sens du lien.
 * @returns {{node: object, label: string, outgoing: boolean}[]}
 */
export function neighboursOf(model, id) {
  const byId = new Map((model?.nodes ?? []).map((node) => [node.id, node]));
  const result = [];
  for (const edge of model?.edges ?? []) {
    if (edge.from === id && byId.has(edge.to)) {
      result.push({ node: byId.get(edge.to), label: edge.label, outgoing: true });
    } else if (edge.to === id && byId.has(edge.from)) {
      result.push({ node: byId.get(edge.from), label: edge.label, outgoing: false });
    }
  }
  return result;
}

/** Nombre de voisins cités dans la description : au-delà, la phrase devient illisible à l'oreille. */
const SPOKEN_NEIGHBOURS = 3;

/**
 * Phrase annoncée pour un nœud, lue par un lecteur d'écran et affichée sous le graphe.
 * @param {object} model modèle rendu par toGraphModel
 * @param {string} id identifiant du nœud
 * @param {{position?: number, total?: number}} [place] rang dans le parcours, pour se repérer
 */
export function describeNode(model, id, place = {}) {
  const node = (model?.nodes ?? []).find((n) => n.id === id);
  if (!node) return '';
  const file = String(node.title ?? '').split('\n')[1];
  const neighbours = neighboursOf(model, id);
  const cited = neighbours.slice(0, SPOKEN_NEIGHBOURS).map((link) => (link.outgoing
    ? `${link.label} ${link.node.label}`
    : `${link.node.label} ${link.label} ce nœud`));
  const links = neighbours.length
    ? `${neighbours.length} lien${neighbours.length > 1 ? 's' : ''} : ${cited.join(', ')}`
      + `${neighbours.length > cited.length ? '...' : ''}.`
    : 'Aucun lien.';
  return [
    place.position && place.total ? `${place.position} sur ${place.total}.` : '',
    `${node.label}, ${NODE_KIND_LABELS[node.kind] ?? 'nœud'}${file ? ` dans ${file}` : ''}.`,
    links,
  ].filter(Boolean).join(' ');
}

/**
 * Nœuds reliés (dans les deux sens) à un ou plusieurs nœuds de départ, parcours en largeur.
 * @param {string | string[]} start nœud(s) de départ
 * @param {number} [maxDepth] distance maximale (en liens)
 * @param {number} [maxNodes] nombre maximal de nœuds retenus (les plus proches d'abord)
 */
export function neighbourhood(start, edges, maxDepth = Infinity, maxNodes = Infinity) {
  const adjacency = new Map();
  for (const { from, to } of edges) {
    if (!adjacency.has(from)) adjacency.set(from, []);
    if (!adjacency.has(to)) adjacency.set(to, []);
    adjacency.get(from).push(to);
    adjacency.get(to).push(from);
  }
  const starts = (Array.isArray(start) ? start : [start]).slice(0, maxNodes);
  const seen = new Set(starts);
  const queue = starts.map((id) => [id, 0]);
  while (queue.length > 0 && seen.size < maxNodes) {
    const [current, depth] = queue.shift();
    if (depth >= maxDepth) continue;
    for (const next of adjacency.get(current) ?? []) {
      if (!seen.has(next)) {
        seen.add(next);
        queue.push([next, depth + 1]);
        if (seen.size >= maxNodes) break;
      }
    }
  }
  return seen;
}

/** Nœuds dont le nom ou le fichier contient le texte cherché (sans tenir compte de la casse). */
export function searchNodes(report, query) {
  const needle = String(query ?? '').trim().toLowerCase();
  if (!needle) return [];
  return (report?.callGraph?.nodes ?? [])
    .filter((n) => `${n.label} ${n.file ?? ''}`.toLowerCase().includes(needle))
    .map((n) => n.id);
}

/**
 * Nœud correspondant à un emplacement de code (constat de sécurité) : fonction du même fichier déclarée juste
 * avant la ligne, sinon n'importe quel nœud du fichier.
 */
export function nodeForLocation(report, file, line) {
  const withFile = (report?.callGraph?.nodes ?? []).filter((n) => n.file && file);
  let inFile = withFile.filter((n) => n.file === file);
  if (!inFile.length) {
    // Chemins exprimés différemment (module, racine) : accepté seulement s'il n'y a qu'un fichier candidat.
    const suffix = withFile.filter((n) => n.file.endsWith(`/${file}`) || file.endsWith(`/${n.file}`));
    inFile = new Set(suffix.map((n) => n.file)).size === 1 ? suffix : [];
  }
  const before = inFile.filter((n) => n.line != null && line != null && n.line <= line)
    .sort((a, b) => b.line - a.line);
  return (before[0] ?? inFile[0])?.id ?? null;
}
