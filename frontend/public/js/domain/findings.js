// Logique pure des constats de sécurité et de la préparation post-quantique (sans DOM, testée sous Node).

import { originOf } from './report.js';
import { SEVERITIES } from './labels.js';

export const CATEGORY_LABELS = Object.freeze({
  secret: 'Secret exposé',
  'certificate-validation': 'Validation TLS désactivée',
  'weak-random': 'Aléa prévisible',
  'hardcoded-key-material': 'Clé / IV en dur',
  'weak-key-derivation': 'Dérivation de clé faible',
  'weak-cipher-suite': 'Suite TLS faible',
  'insecure-protocol-config': 'Configuration TLS/SSH risquée',
  'insecure-jwt': 'JWT non vérifié',
});

/** Étapes de migration post-quantique (PqcReadiness.Stage côté serveur). */
export const PQC_STAGES = Object.freeze({
  'no-asymmetric': { label: 'Pas de cryptographie asymétrique', tone: 'neutral',
    advice: 'Rien à migrer : la cryptographie symétrique n\'est affaiblie que par Grover (préférer AES-256).' },
  'not-started': { label: 'Migration non commencée', tone: 'serious',
    advice: 'RSA / ECC / DH seront cassés par un ordinateur quantique (Shor). Inventorier les usages, puis passer '
      + 'à ML-KEM (échange de clés) et ML-DSA / SLH-DSA (signature), en hybride pendant la transition. Les données '
      + 'chiffrées aujourd\'hui peuvent être stockées et déchiffrées plus tard ("récolter maintenant, déchiffrer '
      + 'plus tard") : prioriser les échanges de clés.' },
  'in-transition': { label: 'Transition en cours', tone: 'warning',
    advice: 'Des algorithmes post-quantiques coexistent avec des algorithmes vulnérables : poursuivre le '
      + 'remplacement, en commençant par les échanges de clés et les secrets à longue durée de vie.' },
  ready: { label: 'Prêt pour le post-quantique', tone: 'good',
    advice: 'Toute la cryptographie asymétrique détectée est post-quantique ou hybride.' },
});

export function severityRank(severity) {
  const rank = SEVERITIES.indexOf(severity);
  return rank < 0 ? 0 : rank;
}

/** Constats les plus graves d'abord, puis par fichier et ligne. */
export function sortFindings(findings, key = 'severity') {
  const byLocation = (a, b) => (a.file ?? '').localeCompare(b.file ?? '') || (a.line ?? 0) - (b.line ?? 0);
  const comparators = {
    severity: (a, b) => severityRank(b.severity) - severityRank(a.severity) || byLocation(a, b),
    category: (a, b) => (CATEGORY_LABELS[a.category] ?? a.category).localeCompare(CATEGORY_LABELS[b.category]
      ?? b.category, 'fr') || severityRank(b.severity) - severityRank(a.severity),
    file: byLocation,
  };
  return [...findings].sort(comparators[key] ?? comparators.severity);
}

/**
 * @param {object} filters { severity: gravité minimale, category, text, includeTests }
 */
export function filterFindings(findings, { severity = '', category = '', text = '', includeTests = true,
  origin = '', modules = [] } = {}) {
  const minRank = severity ? severityRank(severity) : 0;
  const needle = text.trim().toLowerCase();
  return findings.filter((f) => severityRank(f.severity) >= minRank
    && (!category || f.category === category)
    && (includeTests || !f.testCode)
    && (!origin || originOf(f.file, modules) === origin)
    && (!needle || `${f.title} ${f.file} ${f.ruleId} ${f.evidence ?? ''}`.toLowerCase().includes(needle)));
}

/** Nombre de constats par gravité, du plus grave au moins grave (pour les tuiles et barres). */
export function severityCounts(findings) {
  const counts = new Map();
  for (const finding of findings) counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  return [...counts.entries()]
    .sort(([a], [b]) => severityRank(b) - severityRank(a))
    .map(([key, count]) => ({ key, count, share: findings.length ? count / findings.length : 0 }));
}

/** Vulnérabilités d'une dépendance, les plus urgentes d'abord : exploitées (KEV), puis probabilité EPSS. */
export function sortVulnerabilities(vulnerabilities) {
  return [...vulnerabilities].sort((a, b) => Number(Boolean(b.knownExploited)) - Number(Boolean(a.knownExploited))
    || (b.epss ?? -1) - (a.epss ?? -1) || a.id.localeCompare(b.id));
}
