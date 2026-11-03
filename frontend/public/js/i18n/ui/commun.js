// Libellés partagés par tous les écrans : statuts, gravités, primitives, licences, notifications,
// mises à jour. Le vocabulaire fixé ici est repris partout ailleurs : actif = asset, constat = finding,
// dépôt = repository, interdit = disallowed (comme l'identifiant de statut), responsable = manager.

export const COMMUN = {
  // --- Statuts de politique et gravités
  Recommandé: 'Recommended',
  Acceptable: 'Acceptable',
  Déprécié: 'Deprecated',
  Interdit: 'Disallowed',
  Inconnu: 'Unknown',
  Inconnue: 'Unknown',
  Critique: 'Critical',
  Élevée: 'High',
  Moyenne: 'Medium',
  Faible: 'Low',
  Info: 'Info',
  Aucune: 'None',
  Autre: 'Other',

  // --- Types d'actifs et primitives
  Algorithme: 'Algorithm',
  Certificat: 'Certificate',
  Protocole: 'Protocol',
  Combinaison: 'Combination',
  'Matériel (clé, keystore)': 'Key material (key, keystore)',
  Matériel: 'Key material',
  'Code compilé': 'Compiled code',
  'Chiffrement par blocs': 'Block cipher',
  'Chiffrement par flot': 'Stream cipher',
  'Chiffrement authentifié': 'Authenticated encryption',
  'Chiffrement asymétrique': 'Public-key encryption',
  'Encapsulation de clé (KEM)': 'Key encapsulation (KEM)',
  'Échange de clés': 'Key agreement',
  Signature: 'Signature',
  Hachage: 'Hash',
  "Code d'authentification (MAC)": 'Message authentication code (MAC)',
  'Dérivation de clé': 'Key derivation',
  'Générateur aléatoire': 'Random generator',
  'Fonction extensible (XOF)': 'Extendable-output function (XOF)',

  // --- Fonctions cryptographiques observées dans le code
  chiffrement: 'encryption',
  déchiffrement: 'decryption',
  signature: 'signing',
  vérification: 'verification',
  hachage: 'hashing',
  dérivation: 'derivation',
  génération: 'generation',
  'génération de clé': 'key generation',
  encapsulation: 'encapsulation',
  décapsulation: 'decapsulation',

  // --- Origine d'une détection
  Règles: 'Rules',
  'cdxgen (flux)': 'cdxgen (flow)',

  // --- États d'une analyse
  'En attente': 'Queued',
  'En cours': 'Running',
  Terminée: 'Finished',
  Échec: 'Failed',
  Arrêtée: 'Stopped',

  // --- Licences des dépendances
  Permissive: 'Permissive',
  'Copyleft faible': 'Weak copyleft',
  'Copyleft fort': 'Strong copyleft',
  'À vérifier': 'To check',
  'MIT, Apache-2.0, BSD... : attribution seulement': 'MIT, Apache-2.0, BSD...: attribution only',
  'LGPL, MPL, EPL : publier les modifications de la bibliothèque elle-même':
    'LGPL, MPL, EPL: changes to the library itself must be published',
  "GPL, AGPL : l'œuvre dérivée doit être publiée sous la même licence":
    'GPL, AGPL: the derived work must be published under the same licence',
  "Licence absente ou non reconnue : droits d'usage à vérifier":
    'Licence missing or unrecognised: usage rights need checking',

  // --- Catégories de constats de sécurité
  'Secret exposé': 'Exposed secret',
  'Clé / IV en dur': 'Hardcoded key or IV',
  'Validation TLS désactivée': 'TLS validation disabled',
  'Aléa prévisible': 'Predictable randomness',
  'Dérivation de clé faible': 'Weak key derivation',
  'JWT non vérifié': 'Unverified JWT',
  'Suite TLS faible': 'Weak TLS cipher suite',
  'Configuration TLS/SSH risquée': 'Risky TLS/SSH configuration',

  // --- Préparation post-quantique
  'Pas de cryptographie asymétrique': 'No public-key cryptography',
  'Migration non commencée': 'Migration not started',
  'Transition en cours': 'Migration under way',
  'Prêt pour le post-quantique': 'Post-quantum ready',
  "Rien à migrer : la cryptographie symétrique n'est affaiblie que par Grover (préférer AES-256).":
    'Nothing to migrate: symmetric cryptography is only weakened by Grover (prefer AES-256).',
  ['RSA / ECC / DH seront cassés par un ordinateur quantique (Shor). Inventorier les usages, puis passer '
    + 'à ML-KEM (échange de clés) et ML-DSA / SLH-DSA (signature), en hybride pendant la transition. Les '
    + 'données chiffrées aujourd\'hui peuvent être stockées et déchiffrées plus tard ("récolter maintenant, '
    + 'déchiffrer plus tard") : prioriser les échanges de clés.']:
    'RSA, ECC and DH will be broken by a quantum computer (Shor). Inventory where they are used, then move '
    + 'to ML-KEM (key agreement) and ML-DSA / SLH-DSA (signing), in hybrid mode during the transition. Data '
    + 'encrypted today can be stored and decrypted later ("harvest now, decrypt later"): start with key '
    + 'agreement.',
  ['Des algorithmes post-quantiques coexistent avec des algorithmes vulnérables : poursuivre le '
    + 'remplacement, en commençant par les échanges de clés et les secrets à longue durée de vie.']:
    'Post-quantum algorithms coexist with vulnerable ones: carry on with the replacement, starting with key '
    + 'agreement and long-lived secrets.',
  'Toute la cryptographie asymétrique détectée est post-quantique ou hybride.':
    'All the public-key cryptography found is post-quantum or hybrid.',

  // --- Posture quantique du catalogue
  'cassé par Shor': 'broken by Shor',
  'résistant (post-quantique)': 'resistant (post-quantum)',
  'marge réduite (Grover)': 'reduced margin (Grover)',
  'selon les algorithmes employés': 'depends on the algorithms used',
  'à proscrire': 'to be avoided',
  'Un ordinateur quantique suffisant casse cette cryptographie : prévoir le remplacement.':
    'A large enough quantum computer breaks this cryptography: plan its replacement.',
  'Conçu pour résister à un ordinateur quantique.': 'Designed to withstand a quantum computer.',
  ["Shor ne s'applique pas ; Grover divise la sécurité par deux : viser 256 bits de clé et 384 bits "
    + "d'empreinte."]:
    'Shor does not apply; Grover halves the security level: aim for 256-bit keys and 384-bit hashes.',
  "Déjà à proscrire aujourd'hui, indépendamment de la menace quantique.":
    'Already to be avoided today, quantum threat aside.',
  'Protocole ou entrée générique : la résistance dépend des algorithmes réellement négociés.':
    'Protocol or generic entry: resistance depends on the algorithms actually negotiated.',

  // --- Origine d'un fichier dans le rapport
  'code du projet': 'project code',
  'dépendance embarquée': 'vendored dependency',
  'sous-module Git': 'Git submodule',
  'code de test': 'test code',
  'Fichier du dépôt analysé : à corriger chez vous.':
    'File from the analysed repository: yours to fix.',
  'Code tiers recopié dans le dépôt (node_modules, vendor...) : à mettre à jour plutôt qu\'à modifier.':
    'Third-party code copied into the repository (node_modules, vendor...): update it rather than edit it.',
  'Dépôt Git imbriqué, cloné avec le projet : appartient souvent à une autre équipe.':
    'Nested Git repository, cloned with the project: often owned by another team.',
  'Fichier de test : la cryptographie faible y est souvent volontaire (vecteurs de test).':
    'Test file: weak cryptography there is often deliberate (test vectors).',

  // --- Graphe
  'Aucun lien.': 'No link.',
  'fichier de clé': 'key file',
  'appel cryptographique': 'cryptographic call',
  'actif cryptographique': 'cryptographic asset',
  fonction: 'function',
  appelle: 'calls',
  utilise: 'uses',
  écrit: 'writes',
  'lu par': 'read by',
  "Aucun lien à afficher (les fonctions englobantes n'ont pas pu être déterminées).":
    'No link to show (the enclosing functions could not be determined).',
  'Bibliothèque de graphe indisponible.': 'Graph library unavailable.',
  'graphe des appels': 'call graph',

  // --- Notifications
  Notifications: 'Notifications',
  'Aucune notification.': 'No notification.',
  'Nouvelle notification : voir la cloche en haut de page.':
    'New notification: see the bell at the top of the page.',
  'Tout marquer comme lu': 'Mark all as read',
  'Tout voir dans Mon espace': 'See everything in My space',
  'non lue': 'unread',

  // --- Mises à jour de l'application de bureau
  'Installer la nouvelle version': 'Install the new version',
  'Redémarrer et mettre à jour': 'Restart and update',
  'Recharger la page': 'Reload the page',
  Maintenant: 'Now',
  'Maintenant :': 'Now:',
  'Plus tard': 'Later',
  'Plus tard :': 'Later:',
  Annuler: 'Cancel',
  'À la fin des analyses': 'When the analyses finish',
  'À la fin des analyses (recommandé) :': 'When the analyses finish (recommended):',
  'Aucune analyse en cours sur ce poste.': 'No analysis running on this machine.',
  'Installation reportée à la fermeture.': 'Installation postponed until the application closes.',
  "L'application va se fermer, installer la mise à jour et redémarrer (quelques secondes).":
    'The application will close, install the update and restart (a few seconds).',
  "La mise à jour s'installera automatiquement à la fin des analyses.":
    'The update will install by itself once the analyses are finished.',
  'La mise à jour se télécharge en arrière-plan ; vous pouvez continuer à travailler.':
    'The update is downloading in the background; you can carry on working.',
  ["Vos analyses, comptes et paramètres sont conservés. Enregistrez d'abord une modification en cours "
    + '(catalogue, paramètres) : la page sera rechargée.']:
    'Your analyses, accounts and settings are kept. Save any edit in progress first (catalog, settings): the '
    + 'page will be reloaded.',
  "l'application redémarre d'elle-même dès que la file est vide. Vous pouvez continuer à travailler.":
    'the application restarts by itself as soon as the queue is empty. You can carry on working.',
  "la mise à jour s'installera à la fermeture de l'application.":
    'the update will install when the application closes.',
  'depuis le début après le redémarrage (aucune n\'est perdue).':
    'from the start after the restart (none is lost).',

  // --- Barre du haut et messages généraux
  'Aller au contenu': 'Skip to content',
  Analyses: 'Analyses',
  Catalogue: 'Catalog',
  Groupes: 'Groups',
  Administration: 'Administration',
  Aide: 'Help',
  'À propos': 'About',
  'Navigation principale': 'Main navigation',
  "Langue de l'interface": 'Interface language',
  'Changer de thème': 'Switch theme',
  'Passer au thème clair': 'Switch to the light theme',
  'Passer au thème sombre': 'Switch to the dark theme',
  Déconnexion: 'Sign out',
  'Déconnecté.': 'Signed out.',
  'Session expirée : reconnectez-vous.': 'Session expired: sign in again.',
  Erreur: 'Error',
  'Chargement...': 'Loading...',
  'Copié.': 'Copied.',
  'Copie impossible : sélectionnez le texte et utilisez Ctrl+C.':
    'Copy failed: select the text and press Ctrl+C.',
};
