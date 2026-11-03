import { api } from '../api.js';
import { CATEGORY_LABELS, PQC_STAGES, sortFindings } from '../domain/findings.js';
import { formatDate, plural, shortTarget } from '../domain/format.js';
import { SEVERITY_LABELS, label, statusInfo } from '../domain/labels.js';
import { badge, emptyState, h, mount } from '../ui/dom.js';

/** Dérive entre deux analyses : ce qui est apparu, a disparu ou a changé de statut. */
export async function renderCompare(container, { baseId, targetId }) {
  mount(container, h('p', { class: 'muted' }, 'Comparaison en cours...'));
  let diff;
  let base;
  try {
    [diff, base] = await Promise.all([api.compareAnalyses(baseId, targetId), api.getAnalysis(baseId)]);
  } catch (error) {
    mount(container, h('section', { class: 'card' }, emptyState(`Comparaison impossible : ${error.message}`),
      h('a', { class: 'button', href: '#/analyses' }, 'Retour aux analyses')));
    return;
  }
  const delta = diff.targetScore - diff.baseScore;
  const tone = delta > 0 ? 'good' : delta < 0 ? 'critical' : 'neutral';
  const stage = (id) => PQC_STAGES[id]?.label ?? id ?? '-';

  mount(container,
    h('section', { class: 'card report-header' },
      h('div', {},
        h('a', { class: 'back-link', href: '#/analyses' }, '<- Analyses'),
        h('h1', {}, `Évolution de ${shortTarget(base.request.target)}`),
        h('p', { class: 'muted small' },
          h('a', { href: `#/report/${diff.baseId}` }, `référence du ${formatDate(diff.baseDate)}`), ' -> ',
          h('a', { href: `#/report/${diff.targetId}` }, `analyse du ${formatDate(diff.targetDate)}`)))),
    h('div', { class: 'card kpis' },
      tile(`${diff.baseScore} -> ${diff.targetScore}`, 'score de sécurité',
        badge({ label: `${delta > 0 ? '+' : ''}${delta}`, icon: delta >= 0 ? '▲' : '▼', tone })),
      tile(String(diff.findingsNew.length), 'nouveaux constats', null, diff.findingsNew.length ? 'serious' : null),
      tile(String(diff.findingsResolved.length), 'constats corrigés'),
      tile(String(diff.vulnerabilitiesNew.length), 'nouvelles vulnérabilités', null,
        diff.vulnerabilitiesNew.length ? 'critical' : null),
      tile(diff.basePqcStage === diff.targetPqcStage ? stage(diff.targetPqcStage)
        : `${stage(diff.basePqcStage)} -> ${stage(diff.targetPqcStage)}`, 'post-quantique', null, null, true)),
    section('Nouveaux constats de sécurité', findingsList(diff.findingsNew), 'Aucun nouveau constat.'),
    section('Constats corrigés', findingsList(diff.findingsResolved), 'Aucun constat corrigé.'),
    section('Changements de statut des actifs', diff.statusChanges.length ? h('ul', { class: 'diff-list' },
      diff.statusChanges.map((c) => h('li', {}, h('strong', {}, c.name), ' : ', badge(statusInfo(c.before)), ' -> ',
        badge(statusInfo(c.after))))) : null, 'Aucun changement de statut.'),
    h('div', { class: 'grid-2' },
      section('Actifs apparus', assetList(diff.assetsAdded), 'Aucun.'),
      section('Actifs disparus', assetList(diff.assetsRemoved), 'Aucun.')),
    h('div', { class: 'grid-2' },
      section('Vulnérabilités apparues', vulnerabilityList(diff.vulnerabilitiesNew), 'Aucune.'),
      section('Vulnérabilités corrigées', vulnerabilityList(diff.vulnerabilitiesFixed), 'Aucune.')));
}

/** @param {boolean} textual valeur textuelle (affichée en plus petit qu'un nombre) */
function tile(value, text, extra = null, tone = null, textual = false) {
  return h('div', { class: `stat-tile${tone ? ` tone-${tone}` : ''}` },
    h('div', { class: textual ? 'stat-value stat-text' : 'stat-value' }, value), h('div', { class: 'stat-label' }, text),
    extra);
}

function section(title, content, empty) {
  return h('section', { class: 'card' }, h('h2', {}, title), content ?? emptyState(empty));
}

function findingsList(findings) {
  if (!findings.length) return null;
  return h('ul', { class: 'diff-list' }, sortFindings(findings).map((f) => h('li', {},
    badge({ label: label(SEVERITY_LABELS, f.severity), icon: '!', tone: f.severity === 'critical' ? 'critical'
      : f.severity === 'high' ? 'serious' : 'neutral' }),
    ' ', h('strong', {}, f.title), h('span', { class: 'muted small' }, ` - ${label(CATEGORY_LABELS, f.category)}`),
    h('div', { class: 'small' }, h('code', {}, f.file), f.line ? ` L${f.line}` : ''))));
}

function assetList(assets) {
  if (!assets.length) return null;
  return h('ul', { class: 'diff-list' }, assets.map((a) => h('li', {}, badge(statusInfo(a.status)), ' ', a.name)));
}

function vulnerabilityList(vulnerabilities) {
  if (!vulnerabilities.length) return null;
  return [h('p', { class: 'muted small' }, plural(vulnerabilities.length, 'vulnérabilité')),
    h('ul', { class: 'diff-list' }, vulnerabilities.map((v) => h('li', {},
      h('strong', {}, v.id), ` - ${v.library}`, v.severity ? ` (${v.severity})` : '',
      v.knownExploited ? h('span', { class: 'tag tag-critical' }, 'exploitée') : null)))];
}
