// Visualisations légères en HTML/CSS : lisibles sans couleur (libellé + valeur toujours affichés),
// infobulle au survol, et utilisables au clavier via les boutons de filtre.

import { h } from './dom.js';

/**
 * Jauge du score 0-100 (piste et remplissage de la même teinte, seuil textuel).
 */
export function scoreMeter(score, tone, caption) {
  return h('div', { class: 'meter-block' },
    h('div', { class: 'hero-number' }, String(score), h('span', { class: 'hero-unit' }, '/100')),
    h('div', {
      class: `meter tone-${tone}`, role: 'meter', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': score,
      'aria-label': caption,
    }, h('div', { class: 'meter-fill', style: { width: `${Math.max(0, Math.min(100, score))}%` } })),
    h('div', { class: 'muted small' }, caption));
}

/**
 * Liste de barres horizontales.
 * @param {Array<{key:string,count:number,share:number}>} rows
 * @param {object} options { labelOf(key), toneOf(key) (palette de statut) ou null (teinte unique), onSelect(key) }
 */
export function barList(rows, options = {}) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  return h('ul', { class: 'bar-list' }, rows.map((row) => {
    const label = options.labelOf ? options.labelOf(row.key) : row.key;
    const tone = options.toneOf ? options.toneOf(row.key) : 'series';
    const percent = Math.round(row.share * 100);
    const content = [
      h('span', { class: `bar-label tone-${tone}` }, options.iconOf ? h('span', { class: 'badge-icon', 'aria-hidden': 'true' },
        options.iconOf(row.key)) : null, label),
      h('span', { class: 'bar-track' },
        h('span', { class: `bar-fill tone-${tone}`, style: { width: `${(row.count / max) * 100}%` } })),
      h('span', { class: 'bar-value' }, `${row.count}`, h('span', { class: 'muted' }, ` - ${percent} %`)),
    ];
    const title = `${label} : ${row.count} (${percent} %)`;
    return h('li', { title },
      options.onSelect
        ? h('button', { class: 'bar-row', type: 'button', onclick: () => options.onSelect(row.key) }, content)
        : h('div', { class: 'bar-row' }, content));
  }));
}

/** Tuile d'indicateur : valeur principale et libellé. */
export function statTile(value, label, tone = null) {
  return h('div', { class: `stat-tile${tone ? ` tone-${tone}` : ''}` },
    h('div', { class: 'stat-value' }, String(value)),
    h('div', { class: 'stat-label' }, label));
}
