// Rendu du graphe avec vis-network (chargé globalement depuis /vendor). Les couleurs proviennent des
// variables CSS : le graphe suit automatiquement le thème clair/sombre.
//
// Le graphe n'est construit qu'une fois par vue : chercher un nœud ou choisir un actif ne redessine rien,
// cela sélectionne et zoome dans le graphe déjà en place. Reconstruire coûte plusieurs secondes sur un gros
// projet (disposition par forces), et surtout cela faisait perdre le contexte : on ne voyait plus à quoi
// l'élément cherché était relié.

import { describeNode, keyboardOrder, neighboursOf, toGraphModel } from '../domain/graph.js';
import { emptyState, mount } from './dom.js';

const GRAVITY = -60;
const SPRING_LENGTH = 120;
const STABILIZATION_ITERATIONS = 400;
const IMPROVED_LAYOUT_MAX_NODES = 100;
const FONT_SIZE = 13;
const EDGE_FONT_SIZE = 10;
const ARROW_SCALE = 0.6;
const ASSET_NODE_SIZE = 16;
/** Zoom appliqué quand on amène sur un nœud : assez près pour le lire, sans perdre ses voisins. */
const FOCUS_ZOOM = 1.2;
const KEYBOARD_ZOOM = 1.1;
const FOCUS_ANIMATION = { duration: 400 };
// vis-network verrouille la vue sur le nœud visé par défaut : on ne pouvait plus ni déplacer ni dézoomer,
// la caméra revenait dessus. On amène la vue sur le nœud, puis on rend la main.
const FOCUS_OPTIONS = { locked: false, animation: FOCUS_ANIMATION };

/** Graphe actuellement affiché : conteneur, réseau, données et modèle, pour le réutiliser tel quel. */
let current = null;

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/**
 * Parcours au clavier : le graphe se manipulait uniquement à la souris.
 *
 * Gauche/droite parcourent tous les nœuds (actifs d'abord), haut/bas passent d'un voisin à l'autre du nœud
 * courant, Entrée ouvre le détail d'un actif, Échap rend la main. Chaque déplacement décrit le nœud dans une
 * zone "aria-live" : le graphe devient lisible sans le voir.
 *
 * @param {HTMLElement} holder conteneur du canevas, rendu focalisable
 * @param {object} model modèle du graphe
 * @param {object} instance réseau vis-network
 * @param {(bomRef: string) => void} onSelectAsset
 */
function enableKeyboard(holder, model, instance, onSelectAsset) {
  const order = keyboardOrder(model);
  if (!order.length) return null;
  const announcer = document.createElement('p');
  announcer.className = 'graph-announcer';
  announcer.setAttribute('aria-live', 'polite');
  holder.after(announcer);

  let index = -1;
  const goTo = (position) => {
    index = (position + order.length) % order.length;
    const node = order[index];
    instance.selectNodes([node.id]);
    instance.focus(node.id, { scale: KEYBOARD_ZOOM, locked: false, animation: { duration: 250 } });
    announcer.textContent = describeNode(model, node.id, { position: index + 1, total: order.length });
  };

  holder.tabIndex = 0;
  holder.setAttribute('role', 'application');
  holder.setAttribute('aria-roledescription', 'graphe des appels');
  holder.setAttribute('aria-label', `Graphe : ${order.length} nœuds. Flèches gauche et droite pour parcourir, `
    + 'haut et bas pour suivre les liens, Entrée pour ouvrir un actif, Échap pour sortir.');

  holder.addEventListener('keydown', (event) => {
    if (event.altKey || event.ctrlKey || event.metaKey) return;
    const node = index >= 0 ? order[index] : null;
    switch (event.key) {
      case 'ArrowRight':
      case 'ArrowDown': {
        // Bas : suivre les liens du nœud courant ; à défaut, avancer dans la liste.
        const neighbours = event.key === 'ArrowDown' && node ? neighboursOf(model, node.id) : [];
        const next = neighbours.length
          ? order.findIndex((n) => n.id === neighbours[0].node.id) : index + 1;
        goTo(next >= 0 ? next : index + 1);
        break;
      }
      case 'ArrowLeft':
      case 'ArrowUp': {
        const neighbours = event.key === 'ArrowUp' && node ? neighboursOf(model, node.id) : [];
        const previous = neighbours.length
          ? order.findIndex((n) => n.id === neighbours[neighbours.length - 1].node.id) : index - 1;
        goTo(previous >= 0 ? previous : index - 1);
        break;
      }
      case 'Home':
        goTo(0);
        break;
      case 'End':
        goTo(order.length - 1);
        break;
      case 'Enter':
        if (node?.assetRef) onSelectAsset(node.assetRef);
        else return;
        break;
      case 'Escape':
        instance.unselectAll();
        announcer.textContent = '';
        index = -1;
        holder.blur();
        break;
      default:
        return; // Tab, zoom du navigateur... : comportement normal.
    }
    event.preventDefault();
  });

  // Prendre le focus sans rien dire laisserait l'utilisateur devant un canevas muet.
  holder.addEventListener('focus', () => {
    if (index < 0) goTo(0);
  });
  return announcer;
}

/** Ce qui détermine le contenu affiché : tant que cela ne change pas, le graphe n'a pas à être refait. */
function signatureOf(report, options) {
  return JSON.stringify([report?.analysisId ?? '', Boolean(options.hideApis),
    [...(options.include ?? [])].sort()]);
}

/**
 * Construit le graphe, ou réutilise celui déjà affiché si le contenu demandé est le même.
 *
 * @param {HTMLElement} holder conteneur du canevas
 * @param {object} report rapport complet
 * @param {object} options { hideApis, include: nœuds à garder dans une vue partielle, highlight: nœuds à
 *        sélectionner et cadrer une fois la disposition calculée }
 * @param {(bomRef: string) => void} onSelectAsset clic sur un actif
 * @returns {{shown: number, total: number, partial: boolean, reused: boolean} | null}
 */
export function renderGraph(holder, report, options, onSelectAsset) {
  if (!window.vis) {
    mount(holder, emptyState('Bibliothèque de graphe indisponible.'));
    return null;
  }
  const signature = signatureOf(report, options);
  if (current && current.holder === holder && current.signature === signature && holder.firstChild) {
    // Même contenu, même conteneur : on garde la disposition, le zoom et la sélection en cours.
    if (options.highlight?.length) locateNodes(options.highlight);
    return { ...current.result, reused: true };
  }
  if (current?.network) {
    current.network.destroy();
    current = null;
  }
  const model = toGraphModel(report, options);
  if (model.nodes.length === 0) {
    mount(holder, emptyState('Aucun lien à afficher (les fonctions englobantes n\'ont pas pu être déterminées).'));
    return { shown: 0, total: model.total, partial: false, reused: false };
  }
  const text = cssVar('--text-primary');
  const muted = cssVar('--text-secondary');
  const surface = cssVar('--surface-1');
  const nodes = model.nodes.map((node) => {
    const color = cssVar(node.colorToken) || muted;
    return {
      id: node.id,
      label: node.label,
      title: node.title,
      shape: node.shape,
      size: node.kind === 'asset' ? ASSET_NODE_SIZE : undefined,
      color: { background: node.kind === 'asset' ? color : surface, border: color,
        highlight: { background: color, border: text } },
      font: { color: text, size: FONT_SIZE, face: 'inherit' },
      borderWidth: 2,
      assetRef: node.assetRef,
    };
  });
  const edges = model.edges.map((edge) => ({
    id: edge.id, from: edge.from, to: edge.to, label: edge.label, dashes: edge.dashed,
    arrows: { to: { enabled: true, scaleFactor: ARROW_SCALE } },
    color: { color: muted, highlight: text },
    font: { size: EDGE_FONT_SIZE, color: muted, strokeWidth: 0, align: 'middle' },
  }));

  holder.replaceChildren();
  const data = { nodes: new window.vis.DataSet(nodes), edges: new window.vis.DataSet(edges) };
  // Disposition par forces calculée une fois (stabilisation), puis figée : lisible quel que soit le
  // nombre de composantes, et le graphe ne "bouge" plus pendant la lecture.
  const network = new window.vis.Network(holder, data, {
    layout: { improvedLayout: nodes.length <= IMPROVED_LAYOUT_MAX_NODES },
    physics: {
      solver: 'forceAtlas2Based',
      forceAtlas2Based: { gravitationalConstant: GRAVITY, springLength: SPRING_LENGTH, avoidOverlap: 1 },
      stabilization: { iterations: STABILIZATION_ITERATIONS, fit: true },
    },
    interaction: { hover: true, navigationButtons: true, keyboard: true },
  });
  const highlight = (options.highlight ?? []).filter((id) => data.nodes.get(id));
  network.once('stabilizationIterationsDone', () => {
    network.setOptions({ physics: false });
    if (highlight.length) locateNodes(highlight);
    else network.fit();
  });
  network.on('click', (params) => {
    const node = params.nodes.length ? data.nodes.get(params.nodes[0]) : null;
    if (node?.assetRef) onSelectAsset(node.assetRef);
  });
  // Un redessin remplace le canevas : l'annonceur précédent n'a plus lieu d'être.
  holder.parentElement?.querySelectorAll('.graph-announcer').forEach((old) => old.remove());
  enableKeyboard(holder, model, network, onSelectAsset);
  const result = { shown: model.nodes.length, total: model.total, partial: model.partial };
  current = { holder, network, data, model, signature, result };
  return { ...result, reused: false };
}

/**
 * Met en évidence des nœuds du graphe affiché et zoome dessus, sans rien reconstruire.
 *
 * @returns {{found: string[], missing: string[], neighbours: number|null} | null} `missing` : nœuds absents
 *          de la vue (graphe trop gros pour tenir entier) ; `neighbours` : nombre de liens quand un seul
 *          nœud est visé. `null` si aucun graphe n'est affiché.
 */
export function locateNodes(ids, { scale = FOCUS_ZOOM } = {}) {
  if (!current?.network) return null;
  const found = ids.filter((id) => current.data.nodes.get(id));
  const missing = ids.filter((id) => !current.data.nodes.get(id));
  if (found.length === 1) {
    current.network.selectNodes(found);
    current.network.focus(found[0], { ...FOCUS_OPTIONS, scale });
  } else if (found.length > 1) {
    current.network.selectNodes(found);
    current.network.fit({ nodes: found, animation: FOCUS_ANIMATION });
  }
  return { found, missing, neighbours: found.length === 1 ? neighboursOf(current.model, found[0]).length : null };
}

/** Revient à la vue d'ensemble : plus de sélection, tout le graphe à l'écran (sans le recalculer). */
export function resetView() {
  if (!current?.network) return;
  current.network.unselectAll();
  current.network.fit({ animation: FOCUS_ANIMATION });
}
