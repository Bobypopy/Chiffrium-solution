// Feuille imprimable d'un rapport : ce que l'on pose sur la table en revue de sécurité ou en comité.
//
// L'archive ZIP et le JSON s'adressent à des outils ; ici, on vise le papier et le PDF. La page n'existe
// qu'au moment de l'impression : elle est construite à la demande, imprimée, puis retirée du document.

import { PQC_STAGES, severityCounts, sortFindings } from '../domain/findings.js';
import { formatDate, plural, shortTarget } from '../domain/format.js';
import { SEVERITY_LABELS, label, statusInfo } from '../domain/labels.js';
import { priorities, scoreBreakdown, statusDistribution, statusOf } from '../domain/report.js';
import { h, mount } from '../ui/dom.js';

/** Bornes : une revue lit les cas les plus graves, pas 1 000 lignes sur papier. */
const MAX_PRIORITIES = 40;
const MAX_FINDINGS = 60;
const MAX_LIBRARIES = 30;

const SCORE_GROUPS = {
  disallowed: 'actifs interdits',
  deprecated: 'actifs dépréciés',
  unknown: 'actifs de statut inconnu',
  'acceptable-quantum': 'actifs acceptables mais vulnérables au quantique',
  acceptable: 'actifs acceptables',
};

/** Tableau simple : en-têtes, puis lignes déjà mises en forme. */
function table(headers, rows) {
  return h('table', { class: 'print-table' },
    h('thead', {}, h('tr', {}, headers.map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, rows));
}

function section(title, ...content) {
  return h('section', { class: 'print-section' }, h('h2', {}, title), ...content);
}

/** "... et 12 autres" : dire ce qui manque plutôt que de couper en silence. */
function more(total, shown, noun) {
  return total > shown
    ? h('p', { class: 'print-more' }, `... et ${total - shown} ${noun} de plus : voir le rapport complet (JSON) `
      + 'ou l\'application.')
    : null;
}

function identity(job, report) {
  const source = report.source ?? {};
  const lignes = [
    ['Cible', job.request?.target ?? '-'],
    source.branch ? ['Branche', source.branch] : null,
    source.commit ? ['Commit', source.commit] : null,
    ['Analyse', formatDate(job.finishedAt ?? job.createdAt)],
    ['Éditée le', formatDate(new Date().toISOString())],
    ['Outils', Object.entries(report.toolVersions ?? {}).map(([k, v]) => `${k} ${v}`).join(', ') || '-'],
  ].filter(Boolean);
  return table(['Élément', 'Valeur'],
    lignes.map(([cle, valeur]) => h('tr', {}, h('th', { scope: 'row' }, cle), h('td', {}, String(valeur)))));
}

function scoreSection(report) {
  const { summary } = report;
  const parts = scoreBreakdown(report.assets ?? [], { limit: 5 });
  return section('Score et priorités',
    h('p', { class: 'print-score' }, h('strong', {}, `${summary.score} / 100`),
      ' - moyenne pondérée des statuts des actifs cryptographiques.'),
    parts.length
      ? table(['Ce qui pèse le plus', 'Nombre', 'Coût', 'Principaux algorithmes'],
        parts.map((part) => h('tr', {},
          h('td', {}, SCORE_GROUPS[part.key] ?? part.key),
          h('td', {}, String(part.count)),
          h('td', {}, `-${part.points} pts`),
          h('td', {}, part.algorithms.map((a) => `${a.name} (${a.count})`).join(', ')))))
      : h('p', {}, 'Aucun actif ne pèse sur le score.'));
}

function indicators(summary) {
  const lignes = [
    ['Actifs cryptographiques', summary.totalAssets],
    ['Emplacements dans le code', summary.totalOccurrences],
    ['Interdits', summary.byStatus?.disallowed ?? 0],
    ['Dépréciés', summary.byStatus?.deprecated ?? 0],
    ['Vulnérables au quantique', summary.quantumVulnerable],
    ['Dépendances inventoriées', summary.libraries],
    ['Vulnérabilités connues (CVE)', summary.vulnerabilities],
    ['dont activement exploitées (KEV)', summary.knownExploited ?? 0],
    ['Constats de sécurité', summary.findings ?? 0],
  ];
  return table(['Indicateur', 'Valeur'],
    lignes.map(([cle, valeur]) => h('tr', {}, h('th', { scope: 'row' }, cle), h('td', {}, String(valeur)))));
}

function pqcSection(summary) {
  const pqc = summary.pqc;
  if (!pqc) return null;
  const stage = PQC_STAGES[pqc.stage] ?? PQC_STAGES['not-started'];
  return section('Préparation post-quantique',
    h('p', {}, h('strong', {}, stage.label), ' - ', stage.advice ?? ''),
    table(['Élément', 'Nombre'], [
      ['Actifs cassés par un ordinateur quantique (Shor)', pqc.quantumVulnerable],
      ['Actifs déjà post-quantiques', pqc.postQuantum],
      ['Chiffrements symétriques sous 256 bits (Grover, CNSA 2.0)', pqc.symmetricBelow256Bits],
    ].map(([cle, valeur]) => h('tr', {}, h('th', { scope: 'row' }, cle), h('td', {}, String(valeur ?? 0))))));
}

function statusSection(summary) {
  const rows = statusDistribution(summary).map((part) => h('tr', {},
    h('th', { scope: 'row' }, statusInfo(part.key).label),
    h('td', {}, String(part.count)),
    h('td', {}, `${Math.round(part.share * 100)} %`)));
  return rows.length ? section('Conformité à la politique', table(['Statut', 'Actifs', 'Part'], rows)) : null;
}

function prioritySection(report) {
  const tous = (report.assets ?? []).filter((a) => ['disallowed', 'deprecated'].includes(statusOf(a)));
  if (!tous.length) return section('À traiter en priorité', h('p', {}, 'Aucun actif interdit ou déprécié.'));
  const top = priorities(report.assets ?? [], MAX_PRIORITIES);
  return section('À traiter en priorité',
    table(['Statut', 'Actif', 'Emplacements'], top.map((asset) => h('tr', {},
      h('td', {}, statusInfo(statusOf(asset)).label),
      h('td', {}, h('strong', {}, asset.name),
        asset.verdict?.reasons?.length
          ? h('div', { class: 'print-note' }, asset.verdict.reasons.join(' - ')) : null),
      h('td', {}, (asset.occurrences ?? []).slice(0, 3)
        .map((o) => `${o.file}${o.line ? `:${o.line}` : ''}`).join(' - ')
        + (asset.occurrences?.length > 3 ? ` ... (${asset.occurrences.length} au total)` : ''))))),
    more(tous.length, top.length, 'actifs'));
}

function findingsSection(report) {
  const tous = report.findings ?? [];
  if (!tous.length) return section('Constats de sécurité', h('p', {}, 'Aucun constat.'));
  const compte = severityCounts(tous);
  const rows = sortFindings(tous, 'severity').slice(0, MAX_FINDINGS);
  return section('Constats de sécurité',
    h('p', {}, compte.map((c) => `${label(SEVERITY_LABELS, c.key)} : ${c.count}`).join(' - ')),
    table(['Gravité', 'Constat', 'Emplacement', 'Correction attendue'], rows.map((f) => h('tr', {},
      h('td', {}, label(SEVERITY_LABELS, f.severity)),
      h('td', {}, f.title, f.cwe ? h('div', { class: 'print-note' }, f.cwe) : null),
      h('td', {}, h('code', {}, `${f.file}${f.line ? `:${f.line}` : ''}`)),
      h('td', {}, f.recommendation ?? '-')))),
    more(tous.length, rows.length, 'constats'));
}

function librariesSection(report) {
  const vulnerables = (report.libraries ?? []).filter((l) => l.vulnerabilities?.length)
    .sort((a, b) => {
      const kev = Number(b.vulnerabilities.some((v) => v.knownExploited))
        - Number(a.vulnerabilities.some((v) => v.knownExploited));
      return kev || b.vulnerabilities.length - a.vulnerabilities.length;
    });
  if (!vulnerables.length) {
    return section('Dépendances vulnérables',
      h('p', {}, report.libraries?.length
        ? `Aucune vulnérabilité connue sur les ${report.libraries.length} dépendances inventoriées.`
        : 'Aucune dépendance inventoriée.'));
  }
  const rows = vulnerables.slice(0, MAX_LIBRARIES);
  return section('Dépendances vulnérables',
    table(['Dépendance', 'Version', 'Vulnérabilités'], rows.map((lib) => h('tr', {},
      h('td', {}, lib.group ? `${lib.group}/${lib.name}` : lib.name),
      h('td', {}, lib.version ?? '-'),
      h('td', {}, plural(lib.vulnerabilities.length, 'vulnérabilité', 'vulnérabilités'),
        lib.vulnerabilities.some((v) => v.knownExploited) ? ' - exploitée (KEV)' : '',
        h('div', { class: 'print-note' }, lib.vulnerabilities.slice(0, 6).map((v) => v.id).join(', ')))))),
    more(vulnerables.length, rows.length, 'dépendances'));
}

/**
 * Feuille imprimable complète.
 * @param {object} job    analyse (cible, dates)
 * @param {object} report rapport chargé
 */
export function printableReport(job, report) {
  const titre = job.label ?? shortTarget(job.request?.target);
  return h('div', { class: 'print-sheet' },
    h('header', { class: 'print-head' },
      h('h1', {}, `Rapport cryptographique - ${titre}`),
      h('p', { class: 'print-note' }, 'Chiffrium - inventaire des usages cryptographiques et préparation '
        + 'post-quantique.')),
    identity(job, report),
    scoreSection(report),
    section('Indicateurs', indicators(report.summary)),
    pqcSection(report.summary),
    statusSection(report.summary),
    prioritySection(report),
    findingsSection(report),
    librariesSection(report),
    (report.warnings ?? []).length
      ? section('Avertissements', h('ul', {}, report.warnings.map((w) => h('li', {}, w))))
      : null,
    h('footer', { class: 'print-foot' },
      h('p', {}, 'Analyse statique : elle voit où le code crée ses clés, pas leur valeur ni ce qui se décide à '
        + 'l\'exécution (configuration, coffre), ni les dépendances calculées par un script de build. Les '
        + 'constats sont à confirmer en revue.')));
}

/**
 * Construit la feuille, ouvre la boîte d'impression du système ("Enregistrer en PDF" y est proposé), puis
 * retire la feuille du document.
 */
export function printReport(job, report) {
  const host = document.createElement('div');
  host.className = 'print-host';
  mount(host, printableReport(job, report));
  document.body.append(host);
  const cleanup = () => {
    host.remove();
    window.removeEventListener('afterprint', cleanup);
  };
  window.addEventListener('afterprint', cleanup);
  window.print();
  // Certains navigateurs n'émettent pas "afterprint" (impression annulée sous Linux, WebKit) : filet.
  setTimeout(cleanup, 60_000);
}
