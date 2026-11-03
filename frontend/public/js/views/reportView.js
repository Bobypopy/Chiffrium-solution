import { api } from '../api.js';
import {
  CATEGORY_LABELS, PQC_STAGES, filterFindings, severityCounts, sortFindings, sortVulnerabilities,
} from '../domain/findings.js';
import { elapsed, formatDate, formatDuration, plural, shortTarget } from '../domain/format.js';
import { nodeForLocation, searchNodes } from '../domain/graph.js';
import { durationEstimate, sameTarget } from '../domain/jobs.js';
import {
  ASSET_TYPE_LABELS, FUNCTION_LABELS, JOB_STATUS_LABELS, JOB_STATUS_STYLES, LICENSE_RISKS, PRIMITIVE_LABELS,
  SEVERITY_LABELS, SOURCE_LABELS, STATUSES, isActiveJob, label, licenseInfo, statusInfo,
} from '../domain/labels.js';
import {
  ORIGINS, assetQuantumPosture, distribution, facets, filterAssets, migrationPlan, occurrencesByFile, originOf,
  priorities, scoreBreakdown, scoreTone, sortAssets, statusDistribution, statusOf,
} from '../domain/report.js';
import { barList, scoreMeter, statTile } from '../ui/charts.js';
import { readPref, writePref } from '../ui/prefs.js';
import { badge, copyText, emptyState, h, mount, toast } from '../ui/dom.js';
import { locateNodes, renderGraph, resetView } from '../ui/graphView.js';
import { printReport } from './printableReport.js';

const TABS = [
  { id: 'dashboard', label: 'Tableau de bord' },
  { id: 'assets', label: 'Actifs' },
  { id: 'migration', label: 'Migration post-quantique' },
  { id: 'findings', label: 'Constats sécurité' },
  { id: 'graph', label: 'Graphe' },
  { id: 'libraries', label: 'Dépendances' },
  { id: 'steps', label: 'Étapes & journal' },
];
const PRIORITY_LIMIT = 8;
const LARGE_GRAPH_NODES = 40;
/** Rapports terminés et filtres déjà chargés, par analyse : la navigation (URL) ne recharge rien. */
const cache = new Map();
const STEP_TONES = { succeeded: 'good', failed: 'critical', skipped: 'muted' };
const STEP_LABELS = { succeeded: 'Réussie', failed: 'Échec', skipped: 'Ignorée' };
const SEVERITY_TONES = { critical: 'critical', high: 'serious', medium: 'warning', low: 'neutral', info: 'muted',
  none: 'muted' };
const SEVERITY_ICONS = { critical: '✕', high: '!', medium: '▲', low: '●', info: 'i', none: '-' };
const PERCENT = 100;
/** Rafraîchissement de la page d'une analyse en attente ou en cours. */
const LIVE_REFRESH_MS = 3000;
let liveTimer = null;
/** Dernier rapport affiché : sélectionner un actif ne doit pas renvoyer en haut d'une liste de 1 000 lignes. */
let lastView = null;
/** Position de lecture relevée avant un changement d'URL interne (le navigateur remonte sinon en haut). */
let scrollBeforeNavigation = null;
/** Journal affiché pendant le suivi en direct, par analyse : texte, défilement, suivi de la fin. */
const logViews = new Map();
/** Marge sous laquelle le journal est considéré "en bas" : il suit alors les nouvelles lignes. */
const LOG_TAIL_MARGIN_PX = 24;
/** Seuil EPSS au-delà duquel une vulnérabilité est mise en avant (probabilité d'exploitation à 30 jours). */
const EPSS_HIGHLIGHT = 0.1;

/**
 * Rapport d'une analyse. `tab` et `selection` viennent de l'URL (#/report/<id>/<onglet>/<bom-ref>).
 */
/** Famille de préférences : les filtres d'un rapport sont gardés par analyse. */
const FILTER_PREFS = 'report-filters';
const DEFAULT_FILTERS = () => ({ status: '', primitive: '', language: '', origin: '', text: '', quantumOnly: false });
const DEFAULT_FINDINGS = () => ({ severity: '', category: '', origin: '', text: '', includeTests: true,
  sort: 'severity' });

/**
 * État des filtres, repris de la visite précédente quand il en existe un.
 *
 * Les valeurs relues sont vérifiées une à une : un stockage abîmé ou d'une version antérieure ne doit pas
 * produire un filtre incompréhensible que l'utilisateur n'arriverait pas à enlever.
 */
function restoreState(id) {
  const saved = readPref(FILTER_PREFS, id);
  const merge = (defaults, values) => {
    const result = { ...defaults };
    for (const key of Object.keys(defaults)) {
      if (values && typeof values[key] === typeof defaults[key]) result[key] = values[key];
    }
    return result;
  };
  return {
    filters: merge(DEFAULT_FILTERS(), saved?.filters),
    sort: typeof saved?.sort === 'string' ? saved.sort : 'risk',
    findings: merge(DEFAULT_FINDINGS(), saved?.findings),
  };
}

/** Vrai si l'état s'écarte des valeurs par défaut : sert à proposer "Réinitialiser" au bon moment. */
function isFiltered(values, defaults) {
  return Object.keys(defaults).some((key) => values[key] !== defaults[key]);
}

export async function renderReport(container, { id, tab = 'dashboard', selection = null, live = false }) {
  clearTimeout(liveTimer);
  if (!live) mount(container, h('p', { class: 'muted' }, 'Chargement du rapport...'));
  let job;
  let report = null;
  try {
    if (cache.has(id)) {
      ({ job, report } = cache.get(id));
    } else {
      job = await api.getAnalysis(id);
      if (job.status === 'succeeded') report = await api.getReport(id);
      if (!isActiveJob(job)) {
        cache.set(id, { job, report, state: null });
      }
    }
  } catch (error) {
    mount(container, h('section', { class: 'card' }, emptyState(`Rapport indisponible : ${error.message}`),
      h('a', { class: 'button', href: '#/analyses' }, 'Retour aux analyses')));
    return;
  }
  const activeTab = report ? tab : 'steps';
  const cached = cache.get(id);
  const state = cached?.state ?? restoreState(id);
  if (cached) cached.state = state;
  // `modules` est injecté par les onglets pour reconnaître les sous-modules : il vient du rapport, pas de
  // l'utilisateur, donc il n'est pas mémorisé.
  state.persist = () => writePref(FILTER_PREFS, id, {
    filters: { ...state.filters, modules: undefined },
    sort: state.sort,
    findings: { ...state.findings, modules: undefined },
  });
  const body = h('div', { class: 'tab-body' });

  const go = (nextTab, ref = null) => {
    // Rester sur le même onglet (on ne fait que choisir un élément) : on garde la position avant que le
    // navigateur ne remonte la page au changement d'ancre.
    scrollBeforeNavigation = nextTab === activeTab ? window.scrollY : null;
    location.hash = `#/report/${id}/${nextTab}${ref ? `/${encodeURIComponent(ref)}` : ''}`;
  };

  const resetAssets = () => {
    Object.assign(state.filters, DEFAULT_FILTERS());
    state.sort = 'risk';
    state.persist();
    renderTab('assets');
  };
  const resetFindings = () => {
    Object.assign(state.findings, DEFAULT_FINDINGS());
    state.persist();
    renderTab('findings');
  };

  const views = {
    dashboard: () => dashboard(report, (filter) => {
      Object.assign(state.filters, filter);
      state.persist();
      renderTab('assets');
    }, (severity) => {
      state.findings.severity = severity;
      state.persist();
      go('findings');
    }, () => go('migration')),
    findings: () => findingsTab(report, state.findings, (target) => go('graph', target),
      { reset: resetFindings, persist: state.persist }),
    assets: () => assetsTab(report, state, selection, (ref) => go('assets', ref), (ref) => go('graph', ref),
      { reset: resetAssets, persist: state.persist }),
    migration: () => migrationTab(report, (ref) => go('assets', ref)),
    graph: () => graphTab(report, selection, (ref) => go('assets', ref)),
    libraries: () => librariesTab(report),
    steps: () => stepsTab(job, report),
  };

  function renderTab(requested) {
    // Onglet venu de l'adresse : seuls les onglets connus sont appelés, jamais une propriété héritée.
    const tabId = Object.hasOwn(views, requested) ? requested : 'dashboard';
    for (const button of tabs.querySelectorAll('[role="tab"]')) {
      button.setAttribute('aria-selected', String(button.dataset.tab === tabId));
    }
    mount(body, views[tabId]());
  }

  const tabs = h('div', { class: 'tabs', role: 'tablist' }, TABS
    .filter((t) => report || t.id === 'steps')
    .map((t) => h('button', {
      role: 'tab', type: 'button', dataset: { tab: t.id }, 'aria-selected': String(t.id === activeTab),
      onclick: () => go(t.id),
    }, t.label)));

  // Même analyse et même onglet (on ne change que l'élément sélectionné) : on garde la position de lecture.
  const sameView = lastView && lastView.id === id && lastView.tab === activeTab;
  const scroll = live ? window.scrollY : sameView ? scrollBeforeNavigation : null;
  scrollBeforeNavigation = null;
  lastView = { id, tab: activeTab };
  mount(container, header(job, report, () => renderReport(container, { id, tab, selection, live: true })), tabs, body);
  renderTab(activeTab);
  if (scroll != null) window.scrollTo(0, scroll);
  if (isActiveJob(job)) {
    // Suivi en direct tant que l'utilisateur reste sur cette analyse.
    const hash = location.hash;
    const refresh = () => {
      if (location.hash !== hash) return;
      // Texte sélectionné à la souris : on attend que la sélection soit relâchée pour ne pas la perdre.
      if (hasSelectionIn(container)) liveTimer = setTimeout(refresh, LIVE_REFRESH_MS);
      else renderReport(container, { id, tab, selection, live: true });
    };
    liveTimer = setTimeout(refresh, LIVE_REFRESH_MS);
  } else {
    logViews.delete(id);
  }
}

/** Vrai si l'utilisateur a sélectionné du texte dans `element`. */
function hasSelectionIn(element) {
  const current = window.getSelection();
  return Boolean(current && !current.isCollapsed && current.rangeCount
    && element.contains(current.getRangeAt(0).commonAncestorContainer));
}

function liveStatus(job, reload) {
  if (isTerminalWithoutReport(job)) {
    const style = JOB_STATUS_STYLES[job.status];
    return h('div', { class: 'live-status' },
      badge({ label: JOB_STATUS_LABELS[job.status], ...style }),
      job.error ? h('span', { class: job.status === 'failed' ? 'error-text' : 'muted' }, job.error) : null);
  }
  if (!isActiveJob(job)) return null;
  const style = JOB_STATUS_STYLES[job.status];
  return h('div', { class: 'live-status', 'aria-live': 'polite' },
    badge({ label: JOB_STATUS_LABELS[job.status], ...style }),
    job.status === 'running'
      ? h('span', {}, `Étape "${job.currentStep ?? '...'}" - ${job.steps.length} terminée(s) - `,
        `${formatDuration(elapsed(job.startedAt, null))} écoulé(es)`)
      : h('span', { class: 'muted' }, 'En attente d\'un emplacement libre (analyses simultanées limitées).'),
    h('span', { class: 'muted small' }, 'Actualisation automatique'),
    stopButton(job, reload, 'Arrêter l\'analyse'),
    job.status === 'running' ? durationHint(job) : null);
}

/**
 * Ordre de grandeur de la durée, tiré des analyses déjà faites.
 *
 * Sans repère, une analyse de cinq minutes donne l'impression d'un blocage. On ne promet pas une durée : on
 * dit ce qu'on a observé, et on le dit aussi quand l'analyse dépasse l'habitude.
 */
function durationHint(job) {
  const hint = h('span', { class: 'muted small' });
  api.listAnalyses().then((jobs) => {
    const estimate = durationEstimate(jobs, job);
    if (!estimate) return;
    const portee = estimate.sameTarget ? 'Sur ce dépôt' : 'Sur les analyses précédentes';
    const fourchette = `${formatDuration(estimate.low)} à ${formatDuration(estimate.high)}`;
    const depasse = elapsed(job.startedAt, null) > estimate.high;
    hint.textContent = depasse
      ? `Plus long que d'habitude (${portee.toLowerCase()} : ${fourchette}). Un gros dépôt ou un clonage lent `
        + 'explique souvent l\'écart.'
      : `${portee} : ${fourchette} (${plural(estimate.sample, 'analyse mesurée', 'analyses mesurées')}).`;
  }).catch(() => {
    // Liste indisponible : on se passe de l'estimation, l'étape en cours reste affichée.
  });
  return hint;
}

/**
 * Bouton d'arrêt avec retour immédiat : l'arrêt est demandé au serveur, qui interrompt les traitements en
 * cours. Pendant un clonage Git, l'interruption n'est effective qu'entre deux phases (jusqu'à une minute sur
 * un gros dépôt) : le bouton reste donc affiché en "Arrêt en cours..." jusqu'au changement de statut.
 */
function stopButton(job, reload, texte) {
  const button = h('button', {
    class: 'button small ghost danger', type: 'button',
    title: 'Les traitements en cours sont interrompus et les fichiers temporaires supprimés. '
      + 'Pendant un clonage, l\'arrêt peut prendre jusqu\'à une minute.',
    onclick: async () => {
      if (!window.confirm('Arrêter cette analyse ? Elle pourra être relancée depuis la liste des analyses.')) return;
      button.disabled = true;
      button.textContent = 'Arrêt en cours...';
      try {
        await api.cancelAnalysis(job.id);
        toast('Arrêt demandé : l\'analyse s\'interrompt (jusqu\'à une minute pendant un clonage).', 'good');
        reload();
      } catch (error) {
        button.disabled = false;
        button.textContent = texte;
        toast(error.message, 'critical');
      }
    },
  }, job.currentStep === 'arrêt en cours' ? 'Arrêt en cours...' : texte);
  button.disabled = job.currentStep === 'arrêt en cours';
  return button;
}

/** Étiquette d'origine d'un fichier : distingue son propre code d'une dépendance recopiée ou d'un sous-module. */
function originTag(file, modules) {
  const origin = originOf(file, modules);
  if (origin === 'project') return null;
  const info = ORIGINS[origin];
  return h('span', { class: 'tag', title: info.hint }, info.label);
}

function isTerminalWithoutReport(job) {
  return job.status === 'failed' || job.status === 'cancelled';
}

function header(job, report, reload) {
  const source = report?.source;
  return h('section', { class: 'report-header card' },
    h('div', {},
      h('a', { class: 'back-link', href: '#/analyses' }, '<- Analyses'),
      h('h1', {}, job.label ?? shortTarget(job.request.target)),
      h('p', { class: 'muted small' }, job.request.target),
      h('p', { class: 'muted small' },
        source?.branch ? `Branche ${source.branch} - ` : '',
        source?.commit ? `commit ${source.commit.slice(0, 10)} - ` : '',
        isActiveJob(job) ? `lancée le ${formatDate(job.createdAt)}`
          : `analysé le ${formatDate(job.finishedAt ?? job.createdAt)}`,
        report ? ` - outils : ${Object.entries(report.toolVersions).map(([k, v]) => `${k} ${v}`).join(', ')}` : ''),
      liveStatus(job, reload)),
    report ? h('div', { class: 'actions' },
      compareSelect(job),
      downloadButton('Télécharger le CBOM (CycloneDX 1.6)', () => api.downloadCbom(job.id), 'primary'),
      downloadButton('Tout télécharger (ZIP)', () => api.downloadBundle(job.id)),
      downloadButton('Rapport complet (JSON)', () => api.downloadReport(job.id)),
      downloadButton('SARIF (revue de code)', () => api.downloadSarif(job.id)),
      downloadButton('Journal (.log)', () => api.downloadLog(job.id)),
      // Mise en page pour une revue ou un comité : l'archive ZIP et le JSON s'adressent à des outils.
      h('button', { class: 'button', type: 'button', title: 'Feuille de revue : score, priorités, constats',
        onclick: () => printReport(job, report) }, 'Imprimer / PDF'))
      : null);
}

/** Liste des autres analyses du même dépôt, chargée à la demande. */
function compareSelect(job) {
  const select = h('select', {
    'aria-label': 'Comparer avec une autre analyse du même dépôt',
    onchange: (e) => {
      const other = e.target.value;
      if (other) location.hash = `#/compare/${other}/${job.id}`;
    },
  }, h('option', { value: '' }, 'Comparer avec...'));
  api.listAnalyses().then((jobs) => {
    const candidates = sameTarget(jobs, job);
    select.hidden = candidates.length === 0;
    select.append(...candidates.map((other) => h('option', { value: other.id },
      `Analyse du ${formatDate(other.createdAt)}${other.summary ? ` (score ${other.summary.score})` : ''}`)));
  }).catch(() => { select.hidden = true; });
  return select;
}

function downloadButton(text, action, variant = 'ghost') {
  return h('button', {
    class: `button ${variant}`, type: 'button',
    onclick: () => action().catch((error) => toast(error.message, 'critical')),
  }, text);
}

function severityBadge(severity) {
  return badge({ label: label(SEVERITY_LABELS, severity), icon: SEVERITY_ICONS[severity] ?? '•',
    tone: SEVERITY_TONES[severity] ?? 'muted' });
}

function dashboard(report, onFilter, onFindings, onMigration) {
  const { summary } = report;
  const tone = scoreTone(summary.score);
  const disallowed = summary.byStatus.disallowed ?? 0;
  const deprecated = summary.byStatus.deprecated ?? 0;
  const top = priorities(report.assets, PRIORITY_LIMIT);

  return h('div', { class: 'dashboard' },
    h('div', { class: 'kpi-row' },
      h('div', { class: 'card score-card' }, h('h2', {}, 'Score de sécurité'),
        scoreMeter(summary.score, tone, 'Moyenne pondérée des statuts des actifs'),
        scoreWhy(report.assets, onFilter)),
      h('div', { class: 'card kpis' },
        statTile(summary.totalAssets, 'actifs cryptographiques'),
        statTile(summary.totalOccurrences, 'emplacements dans le code'),
        statTile(disallowed, 'interdits', disallowed ? 'critical' : null),
        statTile(deprecated, 'dépréciés', deprecated ? 'serious' : null),
        statTile(summary.quantumVulnerable, 'vulnérables au quantique', summary.quantumVulnerable ? 'serious' : null),
        statTile(summary.vulnerabilities, 'CVE sur les dépendances', summary.vulnerabilities ? 'critical' : null),
        statTile(summary.knownExploited ?? 0, 'CVE exploitées (KEV)', summary.knownExploited ? 'critical' : null),
        statTile(summary.findings ?? 0, 'constats de sécurité', summary.findings ? 'serious' : null))),
    h('div', { class: 'grid-2' },
      pqcCard(summary.pqc, onMigration),
      h('section', { class: 'card' }, h('h2', {}, 'Constats de sécurité'),
        report.findings?.length
          ? barList(severityCounts(report.findings), {
            labelOf: (k) => label(SEVERITY_LABELS, k), toneOf: (k) => SEVERITY_TONES[k] ?? 'muted',
            iconOf: (k) => SEVERITY_ICONS[k] ?? '•', onSelect: onFindings,
          })
          : emptyState('Aucun secret, contournement TLS ou aléa faible détecté.'))),
    h('div', { class: 'grid-2' },
      h('section', { class: 'card' }, h('h2', {}, 'Conformité à la politique'),
        barList(statusDistribution(summary), {
          labelOf: (k) => statusInfo(k).label, toneOf: (k) => statusInfo(k).tone, iconOf: (k) => statusInfo(k).icon,
          onSelect: (k) => onFilter({ status: k }),
        })),
      h('section', { class: 'card' }, h('h2', {}, 'Primitives utilisées'),
        barList(distribution(summary.byPrimitive), {
          labelOf: (k) => label(PRIMITIVE_LABELS, k), onSelect: (k) => onFilter({ primitive: k }),
        }))),
    h('div', { class: 'grid-2' },
      h('section', { class: 'card' }, h('h2', {}, 'À traiter en priorité'),
        top.length ? h('ul', { class: 'priority-list' }, top.map((asset) => h('li', {},
          badge(statusInfo(statusOf(asset))),
          h('a', { href: `#/report/${report.analysisId}/assets/${encodeURIComponent(asset.bomRef)}` }, asset.name),
          h('span', { class: 'muted small' }, ` - ${plural(asset.occurrences.length, 'emplacement')}`))))
          : emptyState('Aucun actif interdit ou déprécié.')),
      h('section', { class: 'card' }, h('h2', {}, 'Licences des dépendances'),
        Object.keys(summary.byLicenseRisk ?? {}).length
          ? barList(LICENSE_RISKS.filter((r) => summary.byLicenseRisk[r.id]).map((r) => ({
            key: r.id, count: summary.byLicenseRisk[r.id],
            share: summary.byLicenseRisk[r.id] / Math.max(1, summary.libraries),
          })), { labelOf: (k) => licenseInfo(k).label, toneOf: (k) => licenseInfo(k).tone,
            iconOf: (k) => licenseInfo(k).icon })
          : emptyState('Pas de dépendances (cdxgen non exécuté).'),
        h('p', { class: 'hint' }, 'Copyleft fort : incompatible avec une diffusion propriétaire sans publication du ',
          'code. Inconnue : vérifier les droits d\'usage.')),
      h('section', { class: 'card' }, h('h2', {}, 'Langages (emplacements)'),
        barList(distribution(summary.byLanguage), { onSelect: (k) => onFilter({ language: k }) }),
        modules(report.source))),
    report.warnings.length ? h('section', { class: 'card warnings' }, h('h2', {}, 'Avertissements'),
      h('ul', {}, report.warnings.map((w) => h('li', {}, w)))) : null);
}

/** Libellés au pluriel accordé : "3 actifs interdits" plutôt qu'un statut recopié tel quel. */
const SCORE_GROUP_LABELS = {
  disallowed: ['actif interdit', 'actifs interdits'],
  deprecated: ['actif déprécié', 'actifs dépréciés'],
  unknown: ['actif de statut inconnu', 'actifs de statut inconnu'],
  'acceptable-quantum': ['actif acceptable mais vulnérable au quantique',
    'actifs acceptables mais vulnérables au quantique'],
  acceptable: ['actif acceptable', 'actifs acceptables'],
};

/**
 * "Ce qui pèse le plus dans ce score" : le score seul ne dit pas quoi corriger d'abord.
 * Chaque ligne mène directement aux actifs concernés, filtrés.
 */
function scoreWhy(assets, onFilter) {
  const parts = scoreBreakdown(assets ?? []);
  if (!parts.length) {
    return h('p', { class: 'hint' }, assets?.length
      ? 'Aucun actif ne pèse sur le score : tous sont recommandés par la politique.'
      : 'Aucun actif cryptographique détecté : le score reste à 100.');
  }
  return h('div', { class: 'score-why' },
    h('h3', {}, 'Ce qui pèse le plus'),
    h('ul', {}, parts.map((part) => {
      const [singular, pluralForm] = SCORE_GROUP_LABELS[part.key] ?? ['actif', 'actifs'];
      return h('li', {},
        h('button', {
          type: 'button', class: 'link-button', title: 'Voir ces actifs',
          onclick: () => onFilter({ ...DEFAULT_FILTERS(), status: part.status, quantumOnly: part.quantum }),
        }, plural(part.count, singular, pluralForm)),
        h('span', { class: 'score-loss' }, `-${part.points} pts`),
        part.algorithms.length
          ? h('div', { class: 'muted small' }, part.algorithms.map((a) => a.name).join(', '))
          : null);
    })),
    h('p', { class: 'hint' }, 'Le score est la moyenne des statuts des actifs : traiter les lignes du haut '
      + 'le fait remonter le plus vite.'));
}

function pqcCard(pqc, onMigration) {
  if (!pqc) return h('section', { class: 'card' }, h('h2', {}, 'Post-quantique'), emptyState('Non calculé.'));
  const stage = PQC_STAGES[pqc.stage] ?? PQC_STAGES['not-started'];
  return h('section', { class: 'card' },
    h('h2', {}, 'Préparation post-quantique'),
    badge({ label: stage.label, icon: stage.tone === 'good' ? '✓' : '!', tone: stage.tone }),
    h('dl', { class: 'facts' },
      h('dt', {}, 'Asymétrique vulnérable (Shor)'), h('dd', {}, String(pqc.quantumVulnerable)),
      h('dt', {}, 'Post-quantique ou hybride'), h('dd', {}, String(pqc.postQuantum)),
      h('dt', {}, 'Symétrique < 256 bits'), h('dd', {}, `${pqc.symmetricBelow256Bits} (acceptable, hors CNSA 2.0)`)),
    h('p', { class: 'hint' }, stage.advice),
    pqc.quantumVulnerable ? h('button', { type: 'button', class: 'button small', onclick: onMigration },
      'Voir le plan de migration') : null);
}

/** Catégorie NIST face à un ordinateur quantique : 1 (comme AES-128) à 5 (comme AES-256), 0 si aucune. */
function quantumLevel(strength) {
  if (strength?.nistQuantumLevel == null) return null;
  return strength.nistQuantumLevel === 0 ? '0 : aucune (cassé par un ordinateur quantique ou clé trop courte)'
    : `${strength.nistQuantumLevel} sur 5`;
}

function quantumTag(asset) {
  const posture = assetQuantumPosture(asset);
  return posture ? h('span', { class: `tag tone-${posture.tone}`, title: posture.hint }, posture.label) : null;
}

/**
 * Plan de migration post-quantique : ce qu'un ordinateur quantique casserait, par quoi le remplacer, et où.
 * Un clic sur une ligne ouvre l'actif (emplacements, extraits de code).
 */
function migrationTab(report, onSelect) {
  const plan = migrationPlan(report.assets);
  const pqc = report.summary.pqc;
  const stage = PQC_STAGES[pqc?.stage] ?? PQC_STAGES['not-started'];
  const resistant = report.assets.filter((a) => assetQuantumPosture(a)?.id === 'pqc');
  const intro = h('section', { class: 'card' },
    h('h2', {}, 'Migration post-quantique'),
    pqc ? badge({ label: stage.label, icon: stage.tone === 'good' ? '✓' : '!', tone: stage.tone }) : null,
    h('p', { class: 'hint' }, 'Chaque ligne est un usage qu\'un ordinateur quantique casserait (algorithme de '
      + 'Shor), avec son remplaçant. Les échanges de clés viennent d\'abord : ce qui est chiffré aujourd\'hui peut '
      + 'être enregistré puis déchiffré plus tard.'));
  const done = resistant.length ? h('section', { class: 'card' }, h('h2', {}, 'Déjà post-quantique'),
    h('ul', {}, resistant.map((asset) => h('li', {},
      h('a', { href: `#/report/${report.analysisId}/assets/${encodeURIComponent(asset.bomRef)}` }, asset.name),
      asset.verdict?.strength?.nistQuantumLevel
        ? h('span', { class: 'muted small' }, ` - catégorie NIST ${asset.verdict.strength.nistQuantumLevel}`)
        : null)))) : null;
  if (!plan.length) {
    return h('div', {}, intro, h('section', { class: 'card' }, emptyState(resistant.length
      ? 'Rien à migrer : la cryptographie asymétrique détectée est déjà post-quantique.'
      : 'Aucun usage cassé par un ordinateur quantique détecté.')), done);
  }
  return h('div', {}, intro,
    h('section', { class: 'card table-wrap' }, h('table', { class: 'table selectable' },
      h('thead', {}, h('tr', {}, ['Actif', 'Usage', 'Remplacer par', 'Emplacements']
        .map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', {}, plan.map(({ asset, keyExchange, files }) => h('tr', {
        tabindex: 0, onclick: () => onSelect(asset.bomRef),
        onkeydown: (e) => { if (e.key === 'Enter') onSelect(asset.bomRef); },
      },
      h('td', {}, h('strong', {}, asset.name), h('div', {}, badge(statusInfo(statusOf(asset))))),
      h('td', {}, asset.algorithm?.primitive ? label(PRIMITIVE_LABELS, asset.algorithm.primitive)
        : label(ASSET_TYPE_LABELS, asset.assetType),
      keyExchange ? h('div', { class: 'muted small' }, 'échange de clés : en premier') : null),
      h('td', {}, asset.verdict?.recommendation ?? '-'),
      h('td', {}, plural(asset.occurrences.length, 'emplacement'),
        h('div', { class: 'muted small' }, plural(files, 'fichier')))))))),
    done);
}

function findingsTab(report, state, onShowInGraph, { reset, persist } = {}) {
  const findings = report.findings ?? [];
  const modules = report.source?.modules ?? [];
  state.modules = modules;
  if (!findings.length) {
    return h('section', { class: 'card' }, emptyState('Aucun constat : pas de secret en clair, de validation TLS '
      + 'désactivée, d\'aléa faible, de clé en dur ni de suite TLS obsolète détectés.'));
  }
  const body = h('tbody');
  const count = h('span', { class: 'muted small' });
  const categories = [...new Set(findings.map((f) => f.category))];
  const resetButton = h('button', {
    class: 'button small ghost', type: 'button', hidden: true,
    onclick: () => reset?.(),
  }, 'Réinitialiser les filtres');

  const update = () => {
    const rows = sortFindings(filterFindings(findings, state), state.sort);
    count.textContent = `${rows.length} / ${findings.length} constats`;
    resetButton.hidden = !isFiltered(state, DEFAULT_FINDINGS());
    persist?.();
    mount(body, rows.length ? rows.map((f) => h('tr', {},
      h('td', {}, severityBadge(f.severity), f.testCode ? h('div', { class: 'muted small' }, 'code de test') : null),
      h('td', {}, h('strong', {}, f.title), h('div', { class: 'muted small' }, label(CATEGORY_LABELS, f.category),
        f.cwe ? ` - ${f.cwe}` : '')),
      h('td', {}, h('code', {}, f.file), f.line ? h('span', { class: 'line-number' }, ` L${f.line}`) : null,
        originTag(f.file, modules),
        f.commit ? h('span', { class: 'tag', title: 'Supprimé du code actuel, mais toujours lisible dans l\'historique Git' },
          `historique ${f.commit.slice(0, 8)}`) : null,
        report.callGraph?.nodes?.length && !f.commit ? h('button', {
          class: 'button small ghost graph-link', type: 'button', title: 'Afficher cet emplacement dans le graphe',
          onclick: () => onShowInGraph(`loc:${f.file}:${f.line ?? 0}`),
        }, 'Graphe') : null,
        f.snippet ? h('pre', { class: 'snippet' }, f.snippet) : null,
        f.evidence ? h('div', { class: 'small' }, h('span', { class: 'muted' }, 'Élément : '), f.evidence) : null),
      h('td', { class: 'small' }, f.description ? h('p', {}, f.description) : null,
        h('p', { class: 'recommendation' }, f.recommendation))))
      : h('tr', {}, h('td', { colspan: 4 }, emptyState('Aucun constat ne correspond aux filtres.'))));
  };
  const select = (key, placeholder, options) => h('select', {
    'aria-label': placeholder, onchange: (e) => { state[key] = e.target.value; update(); },
  }, h('option', { value: '' }, placeholder), options.map(([value, text]) => h('option', {
    value, selected: state[key] === value,
  }, text)));
  update();
  return h('div', {},
    h('div', { class: 'filters' },
      h('input', { type: 'search', placeholder: 'Rechercher (titre, fichier, règle)...', 'aria-label': 'Rechercher',
        value: state.text, oninput: (e) => { state.text = e.target.value; update(); } }),
      select('severity', 'Toutes gravités', ['critical', 'high', 'medium', 'low']
        .map((s) => [s, `${label(SEVERITY_LABELS, s)} et plus`])),
      select('category', 'Toutes catégories', categories.map((c) => [c, label(CATEGORY_LABELS, c)])),
      // Distinguer son propre code d'une dépendance recopiée : la correction n'est pas la même.
      select('origin', 'Toutes origines', Object.entries(ORIGINS).map(([id, info]) => [id, info.label])),
      h('label', { class: 'inline-check' }, h('input', {
        type: 'checkbox', checked: state.includeTests,
        onchange: (e) => { state.includeTests = e.target.checked; update(); },
      }), ' Inclure le code de test'),
      h('select', { 'aria-label': 'Trier par', onchange: (e) => { state.sort = e.target.value; update(); } },
        [['severity', 'Tri : gravité'], ['category', 'Tri : catégorie'], ['file', 'Tri : fichier']]
          .map(([value, text]) => h('option', { value, selected: state.sort === value }, text))),
      count, resetButton),
    h('p', { class: 'hint' }, 'Les secrets sont caviardés dans le rapport. Un faux positif peut être ignoré en ajoutant ',
      'le commentaire "chiffrium:ignore" sur la ligne concernée.'),
    h('section', { class: 'card table-wrap' }, h('table', { class: 'table' },
      h('thead', {}, h('tr', {}, ['Gravité', 'Constat', 'Emplacement', 'Risque et correction']
        .map((th) => h('th', { scope: 'col' }, th)))), body)));
}

function modules(source) {
  const list = source?.modules ?? [];
  if (list.length <= 1) return null;
  return h('details', { class: 'modules' },
    h('summary', {}, `${plural(list.length, 'module détecté', 'modules détectés')} (parcours récursif)`),
    h('ul', {}, list.map((m) => h('li', {},
      h('code', {}, m.path), m.gitRepository ? ' - dépôt Git' : '',
      m.languages.length ? ` - ${m.languages.join(', ')}` : '',
      m.manifests.length ? ` - ${m.manifests.join(', ')}` : ''))));
}

function assetsTab(report, state, selection, onSelect, onShowGraph, { reset, persist } = {}) {
  state.filters.modules = report.source?.modules ?? [];
  const { primitives, languages } = facets(report.assets);
  const tableBody = h('tbody');
  const detail = h('aside', { class: 'asset-detail card' });
  const count = h('span', { class: 'muted small' });

  const resetButton = h('button', {
    class: 'button small ghost', type: 'button', hidden: true,
    onclick: () => reset?.(),
  }, 'Réinitialiser les filtres');

  const update = () => {
    const assets = sortAssets(filterAssets(report.assets, state.filters), state.sort);
    count.textContent = `${assets.length} / ${report.assets.length} actifs`;
    resetButton.hidden = !isFiltered(state.filters, DEFAULT_FILTERS()) && state.sort === 'risk';
    persist?.();
    mount(tableBody, assets.length ? assets.map((asset) => assetRow(asset, asset.bomRef === selection, onSelect))
      : h('tr', {}, h('td', { colspan: 6 }, emptyState('Aucun actif ne correspond aux filtres.'))));
  };
  const selected = report.assets.find((a) => a.bomRef === selection);
  mount(detail, selected ? assetDetail(selected, onShowGraph, report.source?.modules ?? [])
    : emptyState('Sélectionnez un actif pour voir le détail.'));

  const select = (key, options, placeholder, labelOf = (v) => v) => h('select', {
    'aria-label': placeholder,
    onchange: (e) => { state.filters[key] = e.target.value; update(); },
  }, h('option', { value: '' }, placeholder), options.map((value) => h('option', {
    value, selected: state.filters[key] === value,
  }, labelOf(value))));

  const filters = h('div', { class: 'filters' },
    h('input', {
      type: 'search', placeholder: 'Rechercher (nom, fichier, fonction)...', value: state.filters.text,
      'aria-label': 'Rechercher', oninput: (e) => { state.filters.text = e.target.value; update(); },
    }),
    select('status', STATUSES.map((s) => s.id), 'Tous les statuts', (v) => statusInfo(v).label),
    select('primitive', primitives, 'Toutes les primitives', (v) => label(PRIMITIVE_LABELS, v)),
    select('language', languages, 'Tous les langages'),
    // Même distinction que dans les constats : son propre code ne se corrige pas comme une dépendance.
    select('origin', Object.keys(ORIGINS), 'Toutes origines', (v) => ORIGINS[v].label),
    h('label', { class: 'inline-check' }, h('input', {
      type: 'checkbox', checked: state.filters.quantumOnly,
      onchange: (e) => { state.filters.quantumOnly = e.target.checked; update(); },
    }), ' Vulnérables au quantique'),
    h('select', {
      'aria-label': 'Trier par', onchange: (e) => { state.sort = e.target.value; update(); },
    }, [['risk', 'Tri : risque'], ['name', 'Tri : nom'], ['occurrences', 'Tri : emplacements']]
      .map(([value, text]) => h('option', { value, selected: state.sort === value }, text))),
    count, resetButton);

  update();
  return h('div', {}, filters, h('div', { class: 'assets-layout' },
    h('div', { class: 'card table-wrap' }, h('table', { class: 'table selectable' },
      h('thead', {}, h('tr', {}, ['Statut', 'Actif', 'Quantique', 'Type / primitive', 'Emplacements', 'Sources']
        .map((t) => h('th', { scope: 'col' }, t)))),
      tableBody)),
    detail));
}

function assetRow(asset, selected, onSelect) {
  return h('tr', {
    class: selected ? 'selected' : '', tabindex: 0,
    onclick: () => onSelect(asset.bomRef),
    onkeydown: (e) => { if (e.key === 'Enter') onSelect(asset.bomRef); },
  },
  h('td', {}, badge(statusInfo(statusOf(asset)))),
  h('td', {}, h('strong', {}, asset.name)),
  h('td', {}, quantumTag(asset)),
  h('td', {}, label(ASSET_TYPE_LABELS, asset.assetType),
    asset.algorithm?.primitive ? h('div', { class: 'muted small' }, label(PRIMITIVE_LABELS, asset.algorithm.primitive)) : null),
  h('td', {}, String(asset.occurrences.length)),
  h('td', { class: 'small' }, asset.sources.map((s) => label(SOURCE_LABELS, s)).join(', ')));
}

function assetDetail(asset, onShowGraph, modules = []) {
  const verdict = asset.verdict ?? {};
  const spec = asset.algorithm;
  const material = asset.material;
  const facts = [
    ['Type', label(ASSET_TYPE_LABELS, asset.assetType)],
    ['Primitive', spec ? label(PRIMITIVE_LABELS, spec.primitive) : null],
    ['Nom dans le code', spec?.rawName],
    ['Taille de clé', spec?.keySize ? `${spec.keySize} bits` : null],
    ['Mode', spec?.mode], ['Bourrage', spec?.padding], ['Courbe', spec?.curve], ['OID', spec?.oid],
    ['Sévérité', label(SEVERITY_LABELS, verdict.severity)],
    ['Face au quantique', assetQuantumPosture(asset)?.label],
    ['Catégorie NIST post-quantique', quantumLevel(verdict.strength)],
    ['Sécurité classique', verdict.strength?.classicalBits ? `${verdict.strength.classicalBits} bits` : null],
    ['Valide jusqu\'en', verdict.validUntil],
    ['Opérations', asset.functions.map((f) => label(FUNCTION_LABELS, f)).join(', ') || null],
    ['Sujet', material?.subject], ['Émetteur', material?.issuer],
    ['Expiration', material?.notValidAfter ? formatDate(material.notValidAfter) : null],
    ['Format', material?.format], ['Description', asset.description],
  ].filter(([, value]) => value != null && value !== '');

  return h('div', {},
    h('div', { class: 'detail-title' }, h('h2', {}, asset.name), badge(statusInfo(statusOf(asset)))),
    verdict.reasons?.length ? h('ul', { class: 'reasons' }, verdict.reasons.map((r) => h('li', {}, r))) : null,
    verdict.recommendation ? h('p', { class: 'recommendation' }, h('strong', {}, 'Recommandation : '),
      verdict.recommendation) : null,
    h('dl', { class: 'facts' }, facts.map(([k, v]) => [h('dt', {}, k), h('dd', {}, String(v))])),
    h('button', { class: 'button ghost small', type: 'button', onclick: () => onShowGraph(asset.bomRef) },
      'Voir dans le graphe'),
    h('h3', {}, `Emplacements (${asset.occurrences.length})`),
    asset.occurrences.length ? occurrencesByFile(asset).map((group) => h('div', { class: 'occurrence-group' },
      h('div', { class: 'occurrence-file' }, h('code', {}, group.file), originTag(group.file, modules)),
      h('ul', {}, group.occurrences.map((o) => h('li', {},
        h('span', { class: 'line-number' }, o.line ? `L${o.line}` : '-'),
        o.function ? h('span', { class: 'muted small' }, ` ${o.function}`) : null,
        o.snippet ? h('pre', { class: 'snippet' }, o.snippet) : null,
        // Valeur venue d'ailleurs (paramètre, champ) : de l'endroit où elle est écrite jusqu'à cet appel.
        o.trace?.length ? h('div', { class: 'trace small' }, h('span', { class: 'muted' }, 'Valeur venue de :'),
          ` ${o.trace.join(' → ')}`) : null,
        o.otherTraces?.length ? h('div', { class: 'trace small' }, h('span', { class: 'muted' }, 'Autres trajets :'),
          h('ul', {}, o.otherTraces.map((t) => h('li', {}, t)))) : null,
        h('span', { class: 'muted small' }, `${label(SOURCE_LABELS, o.source)}${o.ruleId ? ` - ${o.ruleId}` : ''}`))))))
      : emptyState('Aucun emplacement : actif déclaré dans le CBOM de cdxgen sans localisation.'));
}

/**
 * @param {string | null} selection bom-ref d'un actif, "q:<texte>" (recherche) ou "loc:<fichier>:<ligne>"
 *        (emplacement d'un constat de sécurité)
 */
function graphTab(report, selection, onSelectAsset) {
  // Le rôle et l'étiquette sont posés par le rendu, qui connaît le nombre de nœuds et les raccourcis.
  const holder = h('div', { class: 'graph-canvas' });
  const place = selection?.startsWith('loc:') ? /^loc:(.*):(\d+)$/.exec(selection) : null;
  const initialQuery = selection?.startsWith('q:') ? selection.slice(2) : '';
  const assetRef = selection && !place && !initialQuery ? selection : '';
  const assetSelect = h('select', { 'aria-label': 'Repérer un actif dans le graphe' },
    h('option', { value: '' }, 'Tout le graphe'),
    sortAssets(report.assets, 'name').map((a) => h('option', { value: a.bomRef, selected: a.bomRef === assetRef }, a.name)));
  const nodeLabels = [...new Set((report.callGraph?.nodes ?? []).map((n) => n.label))].sort();
  const suggestions = h('datalist', { id: 'graph-nodes' }, nodeLabels.map((label) => h('option', { value: label })));
  const search = h('input', { type: 'search', list: 'graph-nodes', value: initialQuery,
    placeholder: 'Chercher une fonction, un fichier, un algorithme...', 'aria-label': 'Chercher dans le graphe' });
  const status = h('p', { class: 'muted small', 'aria-live': 'polite' });
  // Les API externes doublent souvent la taille du graphe : masquées par défaut sur les gros projets.
  const hideApis = h('input', { type: 'checkbox', checked: (report.callGraph?.nodes?.length ?? 0) > LARGE_GRAPH_NODES });
  const nextMatch = h('button', { class: 'button small ghost', type: 'button', hidden: true,
    onclick: () => step(1) }, 'Résultat suivant');

  // Nœuds qui doivent rester dans la vue même quand le graphe est trop gros pour tenir entier.
  const required = new Set();
  let matches = [];
  let matchIndex = 0;
  let shown = null;

  const partialNote = () => (shown?.partial
    ? `Vue partielle : ${shown.shown} nœuds sur ${shown.total} (les plus risqués d'abord) ; ce que vous cherchez `
      + 'est ajouté à la vue si besoin.'
    : '');

  const draw = (highlight = []) => {
    shown = renderGraph(holder, report, { hideApis: hideApis.checked, include: [...required], highlight },
      onSelectAsset);
    return shown;
  };

  /**
   * Amène la vue sur des nœuds du graphe affiché. Le graphe n'est reconstruit que si la cible n'y est pas
   * (vue partielle d'un très gros projet).
   */
  const locate = (ids, intro) => {
    if (!ids.length) {
      status.textContent = [intro, partialNote()].filter(Boolean).join(' ');
      return;
    }
    let placed = locateNodes(ids);
    if (!placed || placed.missing.length) {
      ids.forEach((id) => required.add(id));
      draw(ids);
      placed = locateNodes(ids) ?? { found: ids, missing: [], neighbours: null };
    }
    const seul = placed.neighbours === 0
      ? 'Ce nœud n\'a aucun lien connu (détection par règle, sans analyse de flux).' : '';
    status.textContent = [intro, seul, partialNote()].filter(Boolean).join(' ');
  };

  /** Passe au résultat suivant quand la recherche en a trouvé plusieurs. */
  function step(direction) {
    if (matches.length < 2) return;
    matchIndex = (matchIndex + direction + matches.length) % matches.length;
    locate([matches[matchIndex]], `Résultat ${matchIndex + 1} sur ${matches.length} pour "${search.value.trim()}".`);
  }

  const runSearch = () => {
    const query = search.value.trim();
    matches = searchNodes(report, query);
    matchIndex = 0;
    nextMatch.hidden = matches.length < 2;
    if (!query) {
      resetView();
      status.textContent = partialNote();
      return;
    }
    if (!matches.length) {
      status.textContent = `Aucun nœud ne contient "${query}". ${partialNote()}`.trim();
      return;
    }
    // Un seul résultat : on zoome dessus. Plusieurs : tous sont sélectionnés, et le bouton fait le tour.
    locate(matches.length === 1 ? matches : matches,
      matches.length === 1 ? `Un résultat pour "${query}", mis en évidence dans le graphe.`
        : `${matches.length} résultats pour "${query}", sélectionnés dans le graphe.`);
  };

  search.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') runSearch();
  });
  search.addEventListener('search', runSearch);
  // Choisir une suggestion de la liste lance la recherche : sans cela, il fallait encore valider.
  search.addEventListener('change', runSearch);
  assetSelect.addEventListener('change', () => {
    matches = [];
    nextMatch.hidden = true;
    if (!assetSelect.value) {
      resetView();
      status.textContent = partialNote();
      return;
    }
    const asset = report.assets.find((a) => a.bomRef === assetSelect.value);
    locate([`asset:${assetSelect.value}`], `${asset?.name ?? 'Actif'} : mis en évidence dans le graphe.`);
  });
  hideApis.addEventListener('change', () => {
    draw();
    status.textContent = partialNote();
  });

  queueMicrotask(() => {
    if (place) {
      const node = nodeForLocation(report, place[1], Number(place[2]));
      if (node) required.add(node);
      draw(node ? [node] : []);
      locate(node ? [node] : [], node ? `Emplacement ${place[1]}:${place[2]}.`
        : `Aucune fonction du graphe ne correspond à ${place[1]}:${place[2]} (fonction non déterminée).`);
    } else if (initialQuery) {
      draw();
      runSearch();
    } else if (assetRef) {
      required.add(`asset:${assetRef}`);
      draw([`asset:${assetRef}`]);
      const asset = report.assets.find((a) => a.bomRef === assetRef);
      locate([`asset:${assetRef}`], `${asset?.name ?? 'Actif'} : mis en évidence dans le graphe.`);
    } else {
      draw();
      status.textContent = partialNote();
    }
  });

  return h('section', { class: 'card' },
    h('div', { class: 'filters' }, search, suggestions,
      h('button', { class: 'button small', type: 'button', onclick: runSearch }, 'Chercher'),
      nextMatch, assetSelect, h('label', { class: 'inline-check' }, hideApis, ' Masquer les API externes')),
    status,
    h('ul', { class: 'legend' },
      [['function', 'Fonction du projet'], ['crypto_api', 'API cryptographique'], ['file', 'Fichier de clé'],
        ['asset', 'Actif (couleur = statut)']]
        .map(([kind, text]) => h('li', {}, h('span', { class: `legend-swatch kind-${kind}`, 'aria-hidden': 'true' }), text))),
    holder,
    h('p', { class: 'muted small' },
      'Chercher ou choisir un actif ne réduit pas le graphe : l\'élément est sélectionné et agrandi à sa place, ',
      'avec ses liens. "Tout le graphe" remet la vue d\'ensemble, sans tout recalculer.'),
    h('p', { class: 'muted small' },
      'Flèches pleines : utilisation, écriture/lecture de fichiers. Pointillés : appels (analyse de flux cdxgen). ',
      'Cliquer sur un actif ouvre son détail. Molette : zoom ; glisser : déplacer.'),
    h('p', { class: 'muted small' },
      'Au clavier : Tab pour entrer dans le graphe, les flèches gauche et droite pour parcourir les nœuds, ',
      'les flèches haut et bas pour suivre les liens, Entrée pour ouvrir un actif, Échap pour sortir. ',
      'Le nœud atteint est décrit sous le graphe.'));
}

function librariesTab(report) {
  const libraries = report.libraries;
  if (!libraries.length) {
    const sbom = report.steps?.find((s) => s.step === 'cdxgen');
    const reason = !sbom || sbom.status === 'skipped'
      ? `cdxgen n'a pas été exécuté${sbom?.message ? ` (${sbom.message})` : ''} : relancez l'analyse avec l'option `
        + '"Exécuter cdxgen" pour inventorier les dépendances.'
      : sbom.status === 'failed' ? `cdxgen a échoué : ${sbom.message ?? "voir l'onglet Étapes & journal"}.`
        : 'Aucune dépendance déclarée trouvée. Les outils de build (Maven, Gradle, sbt...) ne sont pas lancés, pour '
          + 'ne pas exécuter le code analysé : les dépendances sont lues dans les pom.xml, les fichiers Gradle '
          + '(verrous, catalogue, déclarations littérales) et les fichiers de verrouillage npm ou Python. Une '
          + 'dépendance calculée par un script de build n\'est pas vue.';
    return h('section', { class: 'card' }, h('h2', {}, 'Aucune dépendance'), h('p', { class: 'muted' }, reason));
  }
  return h('section', { class: 'card table-wrap' }, h('table', { class: 'table' },
    h('thead', {}, h('tr', {}, ['Dépendance', 'Version', 'Portée', 'Licence', 'Crypto', 'Vulnérabilités']
      .map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, libraries.map((lib) => h('tr', {},
      h('td', {}, h('strong', {}, lib.group ? `${lib.group}/${lib.name}` : lib.name), h('div', { class: 'muted small' }, lib.purl)),
      h('td', {}, lib.version ?? '-'),
      h('td', {}, lib.scope ?? '-'),
      h('td', { title: licenseInfo(lib.licenseRisk).hint }, badge(licenseInfo(lib.licenseRisk)),
        h('div', { class: 'muted small' }, (lib.licenses ?? []).join(', ') || 'non déclarée')),
      h('td', {}, lib.cryptoLibrary ? h('span', { class: 'tag' }, 'crypto') : ''),
      h('td', {}, lib.vulnerabilities.length
        ? h('details', {}, h('summary', {}, plural(lib.vulnerabilities.length, 'vulnérabilité'),
          lib.vulnerabilities.some((v) => v.knownExploited) ? h('span', { class: 'tag tag-critical' }, 'KEV') : null),
          h('ul', {}, sortVulnerabilities(lib.vulnerabilities).map((v) => h('li', {},
            h('a', { href: v.url, target: '_blank', rel: 'noopener noreferrer' }, v.id),
            v.severity ? ` (${v.severity})` : '',
            v.knownExploited ? h('span', { class: 'tag tag-critical', title: 'Catalogue CISA KEV' }, 'exploitée') : null,
            v.epss != null ? h('span', { class: v.epss >= EPSS_HIGHLIGHT ? 'tag tag-serious' : 'tag',
              title: 'Probabilité d\'exploitation à 30 jours (EPSS)' }, `EPSS ${(v.epss * PERCENT).toFixed(1)} %`) : null,
            v.aliases.length ? ` - ${v.aliases.join(', ')}` : '',
            v.summary ? h('div', { class: 'muted small' }, v.summary) : null))))
        : '-'))))));
}

function stepsTab(job, report) {
  // Pendant le suivi en direct, la page est reconstruite toutes les LIVE_REFRESH_MS : on repart du texte et de
  // la position précédents pour que le journal ne se vide pas (la page remonterait) et ne saute pas.
  const previous = logViews.get(job.id);
  const view = previous ?? { text: null, scrollTop: 0, followTail: isActiveJob(job) };
  logViews.set(job.id, view);
  const log = h('pre', {
    class: 'log',
    onscroll: () => {
      view.scrollTop = log.scrollTop;
      view.followTail = log.scrollTop + log.clientHeight >= log.scrollHeight - LOG_TAIL_MARGIN_PX;
    },
  }, view.text ?? 'Chargement du journal...');
  const restore = () => { log.scrollTop = view.followTail ? log.scrollHeight : view.scrollTop; };
  requestAnimationFrame(restore);
  api.getLog(job.id).then((text) => {
    const content = text || '(journal vide)';
    if (content === view.text) return;
    view.text = content;
    // Ne pas remplacer le texte sous une sélection en cours.
    if (!hasSelectionIn(log)) {
      log.textContent = content;
      restore();
    }
  })
    .catch((error) => { log.textContent = `Journal indisponible : ${error.message}`; });
  const steps = report?.steps ?? job.steps ?? [];
  return h('div', {},
    job.error ? h('section', { class: 'card error-box' }, h('h2', {}, 'Échec de l\'analyse'), h('p', {}, job.error)) : null,
    h('section', { class: 'card table-wrap' }, h('h2', {}, 'Étapes'),
      h('table', { class: 'table' },
        h('thead', {}, h('tr', {}, ['Étape', 'Résultat', 'Durée', 'Détail'].map((t) => h('th', { scope: 'col' }, t)))),
        h('tbody', {}, steps.map((step) => h('tr', {},
          h('td', {}, step.step),
          h('td', {}, badge({ label: STEP_LABELS[step.status] ?? step.status, icon: step.status === 'failed' ? '✕' : step.status === 'skipped' ? '-' : '✓',
            tone: STEP_TONES[step.status] ?? 'muted' })),
          h('td', {}, formatDuration(step.durationMs)),
          h('td', { class: 'small' }, step.message ?? '')))))),
    h('section', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', {}, 'Journal'),
      h('div', { class: 'actions' },
        h('button', {
          class: 'button ghost small', type: 'button',
          onclick: () => copyText(view.text ?? log.textContent, 'Journal copié.'),
        }, 'Copier'),
        downloadButton('Télécharger (.log)', () => api.downloadLog(job.id), 'ghost small'))), log));
}
