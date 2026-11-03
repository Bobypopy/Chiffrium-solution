// Libellés et ordres d'affichage : source unique pour toutes les vues (DRY).

/** Statuts de politique, du plus sûr au plus risqué ; `tone` renvoie à la palette de statut CSS. */
export const STATUSES = Object.freeze([
  { id: 'recommended', label: 'Recommandé', icon: '✓', tone: 'good' },
  { id: 'acceptable', label: 'Acceptable', icon: '●', tone: 'neutral' },
  { id: 'unknown', label: 'À vérifier', icon: '?', tone: 'muted' },
  { id: 'deprecated', label: 'Déprécié', icon: '!', tone: 'serious' },
  { id: 'disallowed', label: 'Interdit', icon: '✕', tone: 'critical' },
]);

export const SEVERITIES = Object.freeze(['none', 'info', 'low', 'medium', 'high', 'critical']);

export const SEVERITY_LABELS = Object.freeze({
  none: 'Aucune', info: 'Info', low: 'Faible', medium: 'Moyenne', high: 'Élevée', critical: 'Critique',
});

export const PRIMITIVE_LABELS = Object.freeze({
  'block-cipher': 'Chiffrement par blocs',
  'stream-cipher': 'Chiffrement par flot',
  ae: 'Chiffrement authentifié',
  hash: 'Hachage',
  mac: 'Code d\'authentification (MAC)',
  signature: 'Signature',
  pke: 'Chiffrement asymétrique',
  kem: 'Encapsulation de clé (KEM)',
  kdf: 'Dérivation de clé',
  'key-agree': 'Échange de clés',
  drbg: 'Générateur aléatoire',
  xof: 'Fonction extensible (XOF)',
  combiner: 'Combinaison',
  other: 'Autre',
  unknown: 'Inconnu',
});

export const FUNCTION_LABELS = Object.freeze({
  generate: 'génération', keygen: 'génération de clé', encrypt: 'chiffrement', decrypt: 'déchiffrement',
  digest: 'hachage', tag: 'authentification', keyderive: 'dérivation', sign: 'signature',
  verify: 'vérification', encapsulate: 'encapsulation', decapsulate: 'décapsulation', other: 'autre',
  unknown: 'inconnue',
});

export const ASSET_TYPE_LABELS = Object.freeze({
  algorithm: 'Algorithme',
  protocol: 'Protocole',
  certificate: 'Certificat',
  'related-crypto-material': 'Matériel (clé, keystore)',
});

export const SOURCE_LABELS = Object.freeze({
  cdxgen: 'cdxgen (flux)', rules: 'Règles', material: 'Matériel', binary: 'Code compilé',
});

/** Risque juridique des licences de dépendances (LicenseRisk côté serveur), du moins au plus contraignant. */
export const LICENSE_RISKS = Object.freeze([
  { id: 'permissive', label: 'Permissive', icon: '✓', tone: 'good',
    hint: 'MIT, Apache-2.0, BSD... : attribution seulement' },
  { id: 'weak-copyleft', label: 'Copyleft faible', icon: '●', tone: 'neutral',
    hint: 'LGPL, MPL, EPL : publier les modifications de la bibliothèque elle-même' },
  { id: 'unknown', label: 'Inconnue', icon: '?', tone: 'muted',
    hint: 'Licence absente ou non reconnue : droits d\'usage à vérifier' },
  { id: 'strong-copyleft', label: 'Copyleft fort', icon: '!', tone: 'serious',
    hint: 'GPL, AGPL : l\'œuvre dérivée doit être publiée sous la même licence' },
]);

export function licenseInfo(id) {
  return LICENSE_RISKS.find((r) => r.id === id) ?? LICENSE_RISKS[2];
}

export const JOB_STATUS_LABELS = Object.freeze({
  queued: 'En attente', running: 'En cours', succeeded: 'Terminée', failed: 'Échec', cancelled: 'Arrêtée',
});

/** Présentation des statuts d'analyse : icône + ton (jamais la couleur seule). */
export const JOB_STATUS_STYLES = Object.freeze({
  queued: { icon: '...', tone: 'muted' },
  running: { icon: '↻', tone: 'neutral' },
  succeeded: { icon: '✓', tone: 'good' },
  failed: { icon: '✕', tone: 'critical' },
  cancelled: { icon: '■', tone: 'muted' },
});

/** Analyse encore active (bouton "Arrêter", rafraîchissement automatique). */
export function isActiveJob(job) {
  return job?.status === 'queued' || job?.status === 'running';
}

export function statusInfo(id) {
  return STATUSES.find((s) => s.id === id) ?? STATUSES[2];
}

export function label(table, key) {
  return table[key] ?? key ?? '-';
}
