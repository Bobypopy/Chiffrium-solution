// Derniers textes relevés en parcourant l'application en anglais : étapes d'analyse, sources de données de
// la page À propos, messages du serveur, et quelques phrases de l'interface découpées autrement.

export const COMPLEMENTS = {
  // --- Étapes d'une analyse (libellés produits par le moteur)
  récupération: 'fetch',
  parcours: 'scan',
  'préparation verrous npm': 'npm lockfile preparation',
  'détection règles': 'rule detection',
  'détection cdxgen': 'cdxgen detection',
  'détection matériel': 'key material detection',
  'détection sécurité': 'security detection',
  évaluation: 'evaluation',
  dépendances: 'dependencies',
  vulnérabilités: 'vulnerabilities',
  graphe: 'graph',
  rapport: 'report',
  'désactivé dans la demande': 'switched off in the request',
  'aucune dépendance déclarée': 'no declared dependency',

  // --- Page À propos (services et sources décrits par le serveur)
  'Dépôts Git analysés (clonage à la demande)': 'Git repositories analysed (cloned on demand)',
  'OpenJDK (JRE embarqué)': 'OpenJDK (bundled JRE)',
  'Logiciel propriétaire, usage interne uniquement (voir LICENSE).':
    'Proprietary software, internal use only (see LICENSE).',
  '- Publications du gouvernement américain, domaine public':
    '- United States government publications, public domain',
  '- Utilisation libre avec attribution (FIRST.org)': '- Free to use with attribution (FIRST.org)',
  '- Données sous licences propres à chaque base source (majoritairement CC-BY-4.0)':
    '- Data under the licence of each source database (mostly CC-BY-4.0)',

  // --- Rôles et groupes
  ['Lecteur : consulte les rapports - Analyste : lance des analyses et supprime les siennes - '
    + 'Administrateur : tous les droits']:
    'Viewer: reads reports - Analyst: starts analyses and deletes their own - Administrator: every right',
  ['Privé : visible de ses seuls membres, on y entre sur invitation - Public : visible dans l\'annuaire, '
    + 'chacun peut demander à le rejoindre']:
    'Private: visible to its members only, you join by invitation - Public: listed in the directory, anyone '
    + 'can ask to join',
  '. Selon les paramètres, la création peut être réservée aux administrateurs.':
    '. Depending on the settings, creating one may be reserved for administrators.',
  vous: 'you',

  // --- Aide : explication du score
  ["Moyenne des actifs cryptographiques pondérés par leur statut, sur 100 : à partir de 80 c'est bon, de 60 "
    + 'à 79 à surveiller, en dessous il faut agir. Un algorithme acceptable mais cassable par un ordinateur '
    + 'quantique est pénalisé. Un projet sans cryptographie obtient 100.']:
    'Average of the cryptographic assets weighted by their status, out of 100: from 80 it is good, 60 to 79 '
    + 'deserves watching, below that action is needed. An algorithm that is acceptable but breakable by a '
    + 'quantum computer is penalised. A project without cryptography scores 100.',

  // --- Messages du serveur
  'Aucun relais de courriel configuré (ou envoi désactivé) : enregistrez d\'abord les réglages.':
    'No email relay configured (or sending is off): save the settings first.',
  "Votre compte n'a pas d'adresse de courriel : renseignez-la dans \"Mon compte\".":
    'Your account has no email address: fill it in under "My space".',
  'identifiant déjà utilisé par un compte local': 'username already taken by a local account',
  'state inconnu, expiré ou code absent': 'unknown or expired state, or missing code',
  "Test d'alerte vers le canal d'équipe": 'Alert test to the team channel',
  'Algorithme interne à référencer': 'Internal algorithm to be registered',
  'Pas de référence normative': 'No standards reference',

  // --- Catalogue : noms d'entrées écrits en français
  'Générateur du système': 'System generator',
  'KDF à une étape (SP 800-56C)': 'One-step KDF (SP 800-56C)',
  'KDF de PKCS#12': 'PKCS#12 KDF',
  'KDF du format PVK': 'PVK format KDF',
  'Keccak (pré-standard)': 'Keccak (pre-standard)',
  'BLS (signature agrégeable)': 'BLS (aggregatable signature)',
  'DES-crypt (crypt(3) historique)': 'DES-crypt (historic crypt(3))',
  'Chiffrement authentifié': 'Authenticated encryption',
  interdit: 'disallowed',
  déprécié: 'deprecated',

  // --- Textes d'anciennes analyses (avant le passage de la typographie en ASCII)
  ['Toujours vérifier la signature avec une liste explicite d\'algorithmes autorisés (jamais \u00ab none '
    + '\u00bb) et valider exp, iss et aud.']:
    'Always verify the signature against an explicit list of allowed algorithms (never "none") and validate '
    + 'exp, iss and aud.',
  ['Votre compte n\'a pas d\'adresse de courriel : renseignez-la dans \u00ab Mon compte \u00bb.']:
    'Your account has no email address: fill it in under "My space".',

  // --- Zone de saisie des cibles
  ['https://gitlab.com/groupe/projet.git\nhttps://github.com/organisation/depot.git\n'
    + '(une cible par ligne)']:
    'https://gitlab.com/group/project.git\nhttps://github.com/organisation/repository.git\n'
    + '(one target per line)',

  "journal d'audit": 'audit log',
  'demandes au catalogue': 'catalog requests',

  ['"Exécuter cdxgen" pour inventorier les dépendances.']:
    '"Run cdxgen" to inventory the dependencies.',

  // --- Paramètres
  "587 (STARTTLS), 465 (chiffré d'emblée) ou 25 (relais interne).":
    '587 (STARTTLS), 465 (encrypted from the start) or 25 (internal relay).',
};
