// Aide (questions fréquentes), Mon espace et À propos.

export const AIDE_COMPTE = {
  // --- Aide : sections
  Aide: 'Help',
  Démarrer: 'Getting started',
  'Lire un rapport': 'Reading a report',
  'Travailler en équipe': 'Working as a team',
  'Données et espace disque': 'Data and disk space',
  'Fichiers téléchargeables': 'Downloadable files',
  ['Chiffrium inventorie la cryptographie d\'un projet (algorithmes, clés, certificats, protocoles), '
    + 'la compare à une politique (le catalogue), signale les erreurs de sécurité et prépare la migration '
    + 'post-quantique.']:
    'Chiffrium inventories the cryptography of a project (algorithms, keys, certificates, protocols), '
    + 'compares it against a policy (the catalog), reports security mistakes and prepares the post-quantum '
    + 'migration.',

  // --- Aide : questions
  'Comment lancer une analyse ?': 'How do I start an analysis?',
  ['Page Analyses > "Nouvelle analyse" : collez l\'adresse https d\'un dépôt Git (ou le chemin d\'un dossier '
    + 'de votre ordinateur, en mode local), puis "Lancer l\'analyse". Plusieurs cibles, une par ligne, '
    + 'lancent plusieurs analyses.']:
    'Analyses page > "New analysis": paste the https address of a Git repository (or the path of a folder '
    + 'on your computer, in local mode), then "Start the analysis". Several targets, one per line, start '
    + 'several analyses.',
  'Combien de temps dure une analyse ?': 'How long does an analysis take?',
  ['De quelques secondes (petit dépôt, sans cdxgen) à plusieurs dizaines de minutes (très gros dépôt comme '
    + 'Bouncy Castle avec cdxgen). La progression s\'affiche dans la liste ; "Suivre" ouvre les étapes et le '
    + 'journal en direct.']:
    'From a few seconds (small repository, without cdxgen) to tens of minutes (a very large repository such '
    + 'as Bouncy Castle with cdxgen). Progress shows in the list; "Follow" opens the steps and the live log.',
  'Pourquoi mon analyse reste "En attente" ?': 'Why does my analysis stay "Queued"?',
  ["Le nombre d'analyses simultanées est limité (cdxgen est gourmand en mémoire). La position dans la file "
    + "est indiquée ; elle démarre dès qu'un emplacement se libère."]:
    'The number of simultaneous analyses is limited (cdxgen is memory-hungry). The position in the queue is '
    + 'shown; it starts as soon as a slot frees up.',
  'Puis-je arrêter une analyse ?': 'Can I stop an analysis?',
  ['Oui : bouton "Arrêter" dans la liste ou sur la page de l\'analyse. Une analyse en attente est retirée de '
    + 'la file ; une analyse en cours s\'interrompt (les programmes lancés sont arrêtés, le clone temporaire '
    + 'est supprimé) et passe à l\'état "Arrêtée". Il n\'y a pas de pause : relancez-la ensuite avec "Plus > '
    + 'Relancer l\'analyse", qui reprend les mêmes paramètres.']:
    'Yes: the "Stop" button in the list or on the analysis page. A queued analysis is removed from the '
    + 'queue; a running one is interrupted (the programs it started are stopped, the temporary clone is '
    + 'deleted) and moves to the "Stopped" state. There is no pause: start it again with "More > Run the '
    + 'analysis again", which reuses the same settings.',
  'À quoi sert cdxgen ?': 'What is cdxgen for?',
  ["Il produit l'inventaire des dépendances (SBOM) et suit les flux cryptographiques en Java et Python. Sans "
    + "lui, le moteur de règles (16 langages) s'exécute seul : plus rapide, mais sans dépendances ni "
    + 'vulnérabilités.']:
    'It produces the dependency inventory (SBOM) and follows cryptographic flows in Java and Python. '
    + 'Without it, the rule engine (16 languages) runs on its own: faster, but with no dependencies and no '
    + 'vulnerabilities.',
  'Que signifie le score ?': 'What does the score mean?',
  'Que veulent dire les statuts ?': 'What do the statuses mean?',
  "conforme à l'état de l'art (ex. AES-256-GCM, SHA-256, ML-KEM)":
    'state of the art (e.g. AES-256-GCM, SHA-256, ML-KEM)',
  'encore sûr aujourd\'hui, à suivre (ex. RSA-3072, souvent vulnérable au quantique)':
    'still safe today, to keep an eye on (e.g. RSA-3072, often quantum-vulnerable)',
  'affaibli, à remplacer (ex. SHA-1 pour la signature, RSA-1024, TLS 1.0)':
    'weakened, to be replaced (e.g. SHA-1 for signing, RSA-1024, TLS 1.0)',
  'cassé ou interdit par la politique (ex. MD5, DES, RC4)':
    'broken or disallowed by the policy (e.g. MD5, DES, RC4)',
  'information insuffisante pour trancher (algorithme absent du catalogue, taille de clé inconnue)':
    'not enough information to decide (algorithm missing from the catalog, unknown key size)',
  'Pourquoi "À vérifier" ?': 'Why "To check"?',
  ["L'algorithme n'est pas dans le catalogue ou sa taille de clé / son mode n'a pas pu être déterminé. "
    + "Ouvrez l'actif pour voir les occurrences dans le code ; proposez un ajout au catalogue si besoin."]:
    'The algorithm is missing from the catalog, or its key size or mode could not be determined. Open the '
    + 'asset to see where it appears in the code; propose an addition to the catalog if needed.',
  'Actifs, constats, dépendances : quelle différence ?':
    'Assets, findings, dependencies: what is the difference?',
  ['Les actifs sont les algorithmes, protocoles, certificats et clés trouvés (le CBOM). Les constats sont '
    + 'des erreurs de sécurité (secret dans le code, validation TLS désactivée, IV fixe...). Les '
    + 'dépendances sont les bibliothèques utilisées, avec leurs vulnérabilités connues et leur licence.']:
    'Assets are the algorithms, protocols, certificates and keys found (the CBOM). Findings are security '
    + 'mistakes (a secret in the code, disabled TLS validation, a fixed IV...). Dependencies are the '
    + 'libraries used, with their known vulnerabilities and their licence.',
  'Et le post-quantique ?': 'What about post-quantum?',
  ["Le tableau de bord indique l'étape de migration : RSA, ECDSA, DH... seront cassés par un ordinateur "
    + 'quantique ; les remplaçants sont ML-KEM (échange de clés) et ML-DSA / SLH-DSA (signature), souvent '
    + 'en hybride pendant la transition.']:
    'The dashboard shows the migration stage: RSA, ECDSA, DH... will be broken by a quantum computer; the '
    + 'replacements are ML-KEM (key agreement) and ML-DSA / SLH-DSA (signing), often in hybrid mode during '
    + 'the transition.',
  "Comment voir l'évolution d'un projet ?": 'How do I see how a project evolves?',
  ['Cochez deux analyses terminées du même dépôt dans la liste, puis "Comparer" (ou "Comparer avec..." sur '
    + 'la page du rapport) : actifs apparus ou disparus, constats corrigés, nouvelles vulnérabilités.']:
    'Tick two finished analyses of the same repository in the list, then "Compare" (or "Compare with..." on '
    + 'the report page): assets that appeared or disappeared, findings fixed, new vulnerabilities.',
  'Qui voit mes analyses ?': 'Who sees my analyses?',
  ["Une analyse privée n'est visible que de vous et des administrateurs. Partagée avec un groupe, elle est "
    + 'visible de ses membres. Changez la visibilité à tout moment ("Plus").']:
    'A private analysis is visible only to you and to the administrators. Shared with a group, it is '
    + 'visible to its members. Change the visibility at any time ("More").',
  'Comment rejoindre un groupe ?': 'How do I join a group?',
  ['Page Groupes : acceptez une invitation reçue, ou demandez à rejoindre un groupe public (un responsable '
    + 'accepte). Vous pouvez quitter un groupe à tout moment.']:
    'Groups page: accept an invitation you received, or ask to join a public group (a manager accepts). You '
    + 'can leave a group at any time.',
  "Comment faire changer le classement d'un algorithme ?": 'How do I get an algorithm reclassified?',
  ['Page Catalogue : ouvrez l\'algorithme puis "Proposer une modification" (ou "Proposer un algorithme" s\'il '
    + 'manque). Un administrateur accepte ou refuse avec un motif ; la décision vous est notifiée et tracée.']:
    'Catalog page: open the algorithm then "Propose a change" (or "Propose an algorithm" if it is missing). '
    + 'An administrator approves or rejects it with a reason; you are notified of the decision and it is '
    + 'recorded.',
  'Où sont mes notifications ?': 'Where are my notifications?',
  'La cloche en haut de page ; l\'historique complet est dans "Mon espace" (clic sur votre nom).':
    'The bell at the top of the page; the full history is in "My space" (click your name).',
  'Où sont stockées les données ?': 'Where is the data stored?',
  ['En mode local, dans votre profil (%APPDATA%\\Chiffrium sous Windows), base et rapports chiffrés. En '
    + "mode équipe, sur le serveur de l'équipe."]:
    'In local mode, in your profile (%APPDATA%\\Chiffrium on Windows), with the database and reports '
    + 'encrypted. In team mode, on the team server.',
  'Quelles informations sortent de mon ordinateur ?': 'What information leaves my computer?',
  ['Le clonage des dépôts demandés et, si activées, les requêtes aux bases de vulnérabilités (noms et '
    + 'versions de dépendances, jamais le code). La liste exacte est sur la page À propos.']:
    'The cloning of the repositories you ask for and, if enabled, the queries to vulnerability databases '
    + '(dependency names and versions, never the code). The exact list is on the About page.',
  'Les clones Git remplissent-ils le disque ?': 'Do Git clones fill up the disk?',
  ['Non : chaque clone est temporaire et supprimé à la fin de l\'analyse, même en cas d\'échec ou d\'arrêt. '
    + 'Les restes éventuels (arrêt brutal) sont nettoyés au démarrage et toutes les heures ; Administration '
    + '> Stockage permet aussi de le faire à la main.']:
    'No: each clone is temporary and deleted when the analysis ends, even on failure or after a stop. '
    + 'Leftovers (abrupt shutdown) are cleaned at start-up and every hour; Administration > Storage also '
    + 'does it by hand.',
  'Et les rapports ?': 'And the reports?',
  ['Ils sont conservés selon la politique de rétention (Administration > Paramètres > Conservation) ; '
    + 'supprimez une analyse avec "Plus > Supprimer".']:
    'They are kept according to the retention policy (Administration > Settings > Retention); delete an '
    + 'analysis with "More > Delete".',
  'Que devient une analyse si je ferme l\'application ?':
    'What happens to an analysis if I close the application?',
  ['Une confirmation est demandée ; l\'analyse est interrompue puis reprend automatiquement depuis le début '
    + 'au prochain lancement. Seul un arrêt brutal (plantage, coupure) la marque en échec : relancez-la '
    + 'avec "Plus > Relancer l\'analyse".']:
    'You are asked to confirm; the analysis is interrupted and starts again from the beginning at the next '
    + 'launch. Only an abrupt stop (crash, power cut) marks it as failed: run it again with "More > Run the '
    + 'analysis again".',
  "Comment mettre à jour l'application ?": 'How do I update the application?',
  ['Quand une nouvelle version est disponible, elle se télécharge en arrière-plan puis un bouton "Mettre à '
    + 'jour" apparaît en haut de la fenêtre (ou menu Aide > Rechercher des mises à jour). Si des analyses '
    + 'tournent, choisissez de l\'installer à la fin des analyses, tout de suite (elles reprendront après '
    + "le redémarrage) ou à la fermeture de l'application."]:
    'When a new version is available it downloads in the background, then an "Update" button appears at the '
    + 'top of the window (or Help menu > Check for updates). If analyses are running, choose to install it '
    + 'when they finish, right away (they resume after the restart) or when the application closes.',

  // --- Aide : fichiers
  'CBOM (CycloneDX 1.6, .json)': 'CBOM (CycloneDX 1.6, .json)',
  ["L'inventaire cryptographique standard, lisible par d'autres outils (Dependency-Track, plateformes de "
    + 'conformité).']:
    'The standard cryptographic inventory, readable by other tools (Dependency-Track, compliance '
    + 'platforms).',
  'Rapport complet (.json)': 'Full report (.json)',
  "Tout ce qu'affiche l'interface : actifs, constats, dépendances, graphe, étapes.":
    'Everything the interface shows: assets, findings, dependencies, graph, steps.',
  'SARIF (.sarif)': 'SARIF (.sarif)',
  ["Format des outils d'analyse de code : s'importe dans GitHub, GitLab, Azure DevOps ou SonarQube pour "
    + 'afficher les constats dans les revues de code.']:
    'The code-scanning format: import it into GitHub, GitLab, Azure DevOps or SonarQube to show the '
    + 'findings in code reviews.',
  'Journal (.log)': 'Log (.log)',
  "Le déroulé technique de l'analyse, utile en cas d'échec.":
    'The technical trace of the analysis, useful when it fails.',
  'Tout télécharger (.zip)': 'Download everything (.zip)',
  'Les quatre fichiers ci-dessus dans une seule archive.':
    'The four files above in a single archive.',

  // --- Mon espace
  'Mon espace': 'My space',
  Profil: 'Profile',
  'Profil mis à jour.': 'Profile updated.',
  'Compte local': 'Local account',
  'Authentification unique (SSO)': 'Single sign-on (SSO)',
  'Nom et e-mail peuvent être remplacés à la prochaine connexion SSO.':
    'Name and email may be overwritten at the next SSO sign-in.',
  'Changer mon mot de passe': 'Change my password',
  'Dernière connexion': 'Last sign-in',
  Invitations: 'Invitations',
  'Aucune invitation en attente.': 'No pending invitation.',
  "Demandes d'adhésion envoyées :": 'Join requests sent:',
  'Aucun groupe.': 'No group.',
  "Voir l'annuaire des groupes": 'See the group directory',
  'pour en rejoindre un.': 'to join one.',
  'Mes demandes au catalogue': 'My catalog requests',
  'Aucune demande au catalogue.': 'No catalog request.',
  Réponse: 'Answer',
  Suppression: 'Removal',
  'Tout est marqué comme lu.': 'Everything is marked as read.',
  'Mes données': 'My data',
  'Exporter mes données (JSON)': 'Export my data (JSON)',
  'Téléchargez les données personnelles que Chiffrium conserve sur vous : compte, groupes, favoris,':
    'Download the personal data Chiffrium holds about you: account, groups, favourites,',
  "analyses demandées, demandes au catalogue, notifications et votre historique dans le journal d'audit.":
    'analyses you requested, catalog requests, notifications and your history in the audit log.',
  'Pour une rectification ou une suppression de compte, contactez un administrateur':
    'For a correction or an account deletion, contact an administrator',
  '(voir la page À propos).': '(see the About page).',

  // --- À propos
  'Outil mis à disposition par': 'Tool provided by',
  Licence: 'Licence',
  'Composants tiers': 'Third-party components',
  Composant: 'Component',
  'Services externes contactés': 'External services contacted',
  'Sources de données': 'Data sources',
  'Données personnelles': 'Personal data',
  'Comptes : identifiant, nom affiché, e-mail (facultatif), rôle, groupes, dates de connexion.':
    'Accounts: username, display name, email (optional), role, groups, sign-in dates.',
  ["Journal d'audit : actions sensibles avec l'auteur, la date et l'adresse IP d'origine (finalité : "
    + 'sécurité et traçabilité).']:
    'Audit log: sensitive actions with the author, the date and the source IP address (purpose: security '
    + 'and traceability).',
  ['Code analysé : peut contenir des données personnelles ou des secrets ; les rapports sont chiffrés et '
    + 'les secrets détectés caviardés.']:
    'Analysed code: it may contain personal data or secrets; reports are encrypted and detected secrets are '
    + 'redacted.',
  "Aucune donnée n'est transmise à l'éditeur de l'outil ; aucune mesure d'audience.":
    'No data is sent to the maker of the tool; there is no analytics.',
  ['Seuls des identifiants techniques (nom et version de paquet, identifiant CVE) sont envoyés ; jamais de '
    + 'code source ni de donnée personnelle.']:
    'Only technical identifiers (package name and version, CVE identifier) are sent; never source code nor '
    + 'personal data.',
  'Pour exercer vos droits (accès, rectification, effacement, limitation) :':
    'To exercise your rights (access, correction, erasure, restriction):',
  'Contact données personnelles non renseigné (Administration -> Paramètres).':
    'Data protection contact not filled in (Administration -> Settings).',
};
