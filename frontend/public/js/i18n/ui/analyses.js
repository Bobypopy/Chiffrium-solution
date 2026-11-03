// Écran Analyses (liste, lancement, suivi) et écrans de connexion.

export const ANALYSES = {
  // --- Liste
  Analyses: 'Analyses',
  'Mes analyses': 'My analyses',
  Favoris: 'Favourites',
  'Toutes les analyses visibles': 'All visible analyses',
  'Rechercher une analyse': 'Search for an analysis',
  'Rechercher (dépôt, libellé, demandeur)...': 'Search (repository, label, requester)...',
  Actualiser: 'Refresh',
  Afficher: 'Show',
  Cible: 'Target',
  Statut: 'Status',
  Progression: 'Progress',
  Soumise: 'Submitted',
  Durée: 'Duration',
  Score: 'Score',
  Rapport: 'Report',
  Journal: 'Log',
  'Sélection et favori': 'Selection and favourite',
  'Aucune analyse pour le moment.': 'No analysis yet.',
  'Aucune analyse ne correspond à ce filtre.': 'No analysis matches this filter.',
  'Les analyses partagées avec vos groupes apparaîtront ici.':
    'Analyses shared with your groups will appear here.',
  'Rôle lecteur : consultation des analyses de vos groupes.':
    'Viewer role: you can read the analyses of your groups.',
  "Collez l'adresse d'un dépôt Git dans \"Nouvelle analyse\", puis cliquez sur":
    'Paste the address of a Git repository into "New analysis", then click',
  '"Lancer l\'analyse". Comptez de quelques secondes à plusieurs minutes selon':
    '"Start the analysis". It takes from a few seconds to several minutes depending on',
  "la taille du dépôt ; vous pouvez l'arrêter à tout moment.":
    'the size of the repository; you can stop it at any time.',

  // --- Lancement
  'Nouvelle analyse': 'New analysis',
  "Lancer l'analyse": 'Start the analysis',
  'Dépôts Git (https) ou dossiers autorisés': 'Git repositories (https) or allowed folders',
  "Une cible par ligne (plusieurs analyses sont lancées d'un coup).":
    'One target per line (several analyses are started at once).',
  'Les lignes commençant par # sont ignorées.': 'Lines starting with # are ignored.',
  'Un dossier de votre ordinateur peut aussi être analysé : collez son chemin (ex. C:\\Projets\\mon-appli).':
    'A folder on your computer can be analysed too: paste its path (e.g. C:\\Projects\\my-app).',
  'Dossiers locaux désactivés sur ce serveur : seuls les dépôts Git sont acceptés.':
    'Local folders are disabled on this server: only Git repositories are accepted.',
  'Indiquez au moins une cible.': 'Give at least one target.',
  Branche: 'Branch',
  'branche par défaut': 'default branch',
  'vide = branche principale du dépôt': 'empty = the repository default branch',
  Visibilité: 'Visibility',
  'Privée (vous et les administrateurs)': 'Private (you and the administrators)',
  'modifiable ensuite (menu "Plus")': 'can be changed later (the "More" menu)',
  'Visibilité modifiée.': 'Visibility changed.',
  'Inclure les sous-modules Git': 'Include Git submodules',
  'Clone aussi les dépôts référencés comme sous-modules.':
    'Also clones the repositories referenced as submodules.',
  'Chercher aussi dans l\'historique Git (secrets et clés supprimés)':
    'Also search the Git history (deleted secrets and keys)',
  ['Cherche les secrets et les clés supprimés du code mais restés dans les anciens commits. Clone tout '
    + 'l\'historique : plus long sur les gros dépôts.']:
    'Looks for secrets and keys removed from the code but still present in old commits. Clones the whole '
    + 'history: slower on large repositories.',
  'Exécuter cdxgen (SBOM + analyse de flux)': 'Run cdxgen (SBOM + flow analysis)',
  ['Inventaire des dépendances (SBOM) et flux cryptographiques Java/Python. Plus lent ; sans lui, seul le '
    + "moteur de règles s'exécute (rapide, tous langages)."]:
    'Dependency inventory (SBOM) and Java/Python cryptographic flows. Slower; without it only the rule '
    + 'engine runs (fast, all languages).',
  'Rechercher les vulnérabilités des dépendances (OSV)': 'Look up dependency vulnerabilities (OSV)',
  'Interroge la base publique OSV avec les noms et versions des dépendances (aucun code envoyé).':
    'Queries the public OSV database with dependency names and versions (no code is sent).',
  'Délai maximal de cdxgen (s)': 'cdxgen time limit (s)',
  "au-delà, l'analyse continue sans SBOM ; augmentez-le pour les gros dépôts":
    'beyond that the analysis carries on without an SBOM; raise it for large repositories',
  ['cdxgen est introuvable : les analyses fonctionneront (moteur de règles), mais sans inventaire des '
    + "dépendances ni recherche de vulnérabilités. Sur l'application de bureau, réinstaller la répare ; sur "
    + 'un serveur, vérifier CDXGEN_COMMAND.']:
    'cdxgen cannot be found: analyses will still run (rule engine), but without the dependency inventory or '
    + 'the vulnerability lookup. On the desktop application, reinstalling fixes it; on a server, check '
    + 'CDXGEN_COMMAND.',
  'dossiers locaux autorisés': 'local folders allowed',
  'dossiers locaux désactivés': 'local folders disabled',

  // --- Actions sur une analyse
  'Plus ▾': 'More ▾',
  Arrêter: 'Stop',
  "Arrêter l'analyse": 'Stop the analysis',
  "Arrêter l'analyse (les processus en cours sont interrompus, les fichiers temporaires supprimés)":
    'Stop the analysis (running processes are interrupted, temporary files deleted)',
  'Arrêt...': 'Stopping...',
  'arrêt en cours': 'stopping',
  "Arrêt demandé : l'analyse s'interrompt (jusqu'à une minute pendant un clonage).":
    'Stop requested: the analysis is winding down (up to a minute during a clone).',
  "Relancer l'analyse": 'Run the analysis again',
  'Analyse relancée avec les mêmes paramètres.': 'Analysis started again with the same settings.',
  'Renommer...': 'Rename...',
  "Libellé de l'analyse (vide : nom du dépôt) :": 'Analysis label (empty: repository name):',
  'Libellé enregistré.': 'Label saved.',
  'Supprimer...': 'Delete...',
  'Analyse supprimée.': 'Analysis deleted.',
  'Retirer de la file d\'attente': 'Remove from the queue',
  'Analyse retirée de la file.': 'Analysis removed from the queue.',
  'Ajouter aux favoris': 'Add to favourites',
  'Retirer des favoris': 'Remove from favourites',
  Suivre: 'Follow',
  'Suivre les étapes et le journal en direct': 'Follow the steps and the log live',
  'Étapes et journal': 'Steps and log',
  'Temps écoulé depuis le démarrage': 'Time elapsed since the start',
  'prochaine à démarrer': 'next to start',
  'Comparer les deux analyses sélectionnées': 'Compare the two selected analyses',
  'Sélectionnez une deuxième analyse terminée pour comparer.':
    'Select a second finished analysis to compare.',
  Annuler: 'Cancel',

  // --- Connexion, première installation, mot de passe
  Connexion: 'Sign in',
  'Se connecter': 'Sign in',
  'Connexion en cours...': 'Signing in...',
  Identifiant: 'Username',
  'Mot de passe': 'Password',
  'Mot de passe actuel': 'Current password',
  'Nouveau mot de passe': 'New password',
  Confirmation: 'Confirmation',
  'Nom affiché': 'Display name',
  'Changer le mot de passe': 'Change the password',
  'Les deux mots de passe diffèrent.': 'The two passwords do not match.',
  'Mot de passe modifié. Vos autres sessions ont été fermées.':
    'Password changed. Your other sessions have been closed.',
  'Votre mot de passe est provisoire : choisissez-en un nouveau pour continuer.':
    'Your password is temporary: choose a new one to carry on.',
  'Première installation': 'First installation',
  "Jeton d'installation": 'Setup token',
  'Créer le compte administrateur': 'Create the administrator account',
  'Compte administrateur créé.': 'Administrator account created.',
  "Aucun compte n'existe encore. Le jeton d'installation figure dans le journal du":
    'No account exists yet. The setup token is in the log of the',
  'serveur et dans le fichier data/secrets/setup-token (droits restreints). Il est détruit après usage.':
    'server and in the file data/secrets/setup-token (restricted permissions). It is destroyed after use.',
  "Se connecter avec l'authentification unique (SSO)": 'Sign in with single sign-on (SSO)',
  "La connexion par authentification unique a échoué ou a été refusée.":
    'Single sign-on failed or was refused.',
  'Serveur injoignable': 'Server unreachable',
  "Charte d'utilisation": 'Terms of use',
  'À propos, licences et confidentialité': 'About, licences and privacy',
};
