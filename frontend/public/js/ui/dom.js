// Construction du DOM sans innerHTML : tout texte est inséré comme nœud texte (aucune injection HTML possible).
//
// C'est aussi le seul endroit où un texte devient visible : il y passe par `t()` (voir i18n.js), ce qui rend
// l'interface traduisible sans toucher une seule vue.

import { t } from '../i18n.js';

const TOAST_DURATION_MS = 6000;
/** Attributs qui portent du texte lu par l'utilisateur ou annoncé par un lecteur d'écran. */
const ATTRIBUTS_TRADUITS = new Set(['title', 'placeholder', 'aria-label', 'alt', 'aria-roledescription',
  'aria-placeholder']);

/**
 * h('div', { class: 'card', onclick: fn }, 'texte', enfant, [enfants...])
 * Attributs : `class`, `dataset` (objet), `on<event>` (écouteur), `style` (objet), booléens, autres attributs.
 */
export function h(tag, attributes = {}, ...children) {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes ?? {})) {
    if (value == null || value === false) continue;
    if (name === 'class') element.className = value;
    else if (name === 'dataset') Object.assign(element.dataset, value);
    else if (name === 'style') Object.assign(element.style, value);
    else if (name.startsWith('on') && typeof value === 'function') element.addEventListener(name.slice(2), value);
    else if (value === true) element.setAttribute(name, '');
    else element.setAttribute(name, ATTRIBUTS_TRADUITS.has(name) ? t(String(value)) : String(value));
  }
  append(element, children);
  return element;
}

function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child == null || child === false) continue;
    parent.append(child instanceof Node ? child : document.createTextNode(t(String(child))));
  }
}

export function clear(element) {
  element.replaceChildren();
  return element;
}

export function mount(container, ...children) {
  clear(container);
  append(container, children);
  return container;
}

/** Pastille de statut : icône + libellé (jamais la couleur seule). */
export function badge(info, extraClass = '') {
  return h('span', { class: `badge tone-${info.tone} ${extraClass}`.trim() },
    h('span', { class: 'badge-icon', 'aria-hidden': 'true' }, info.icon), info.label);
}

export function emptyState(message) {
  return h('p', { class: 'empty' }, message);
}

/**
 * Mémorise la position de lecture (page et zones défilantes) et renvoie de quoi y revenir. Sert aux écrans qui
 * ouvrent un formulaire plus haut : après avoir enregistré ou annulé, on retrouve sa ligne au lieu de repartir
 * du haut d'une liste de plusieurs centaines d'entrées.
 */
export function rememberScroll(...zones) {
  const page = window.scrollY;
  const positions = zones.filter(Boolean).map((zone) => [zone, zone.scrollTop]);
  return () => {
    for (const [zone, top] of positions) zone.scrollTop = top;
    window.scrollTo(0, page);
  };
}

/** Notification temporaire (erreurs et confirmations). */
export function toast(message, tone = 'neutral') {
  const region = document.getElementById('toasts');
  if (!region) return;
  const note = h('div', { class: `toast tone-${tone}`, role: 'status' }, message);
  region.append(note);
  setTimeout(() => note.remove(), TOAST_DURATION_MS);
}

/**
 * Copie un texte dans le presse-papiers. L'API Clipboard peut être refusée (page non active, permission) :
 * on se replie alors sur une zone de texte temporaire et execCommand.
 */
export async function copyText(text, done = 'Copié.') {
  try {
    await navigator.clipboard.writeText(text);
    toast(done, 'good');
    return;
  } catch {
    // repli ci-dessous
  }
  const area = h('textarea', { readonly: true, 'aria-hidden': 'true', style: { position: 'fixed', top: '0', left: '-9999px' } });
  area.value = text;
  document.body.append(area);
  area.select();
  const copied = document.execCommand('copy');
  area.remove();
  if (copied) toast(done, 'good');
  else toast('Copie impossible : sélectionnez le texte et utilisez Ctrl+C.', 'critical');
}
