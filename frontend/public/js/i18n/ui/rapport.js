// Rapport d'analyse : tableau de bord, actifs, constats, graphe, dépendances, étapes, impression,
// et comparaison de deux analyses.

export const RAPPORT = {
  // --- Onglets et navigation
  'Tableau de bord': 'Dashboard',
  Actifs: 'Assets',
  'Constats sécurité': 'Security findings',
  'Constats de sécurité': 'Security findings',
  Graphe: 'Graph',
  Dépendances: 'Dependencies',
  'Étapes & journal': 'Steps & log',
  'Retour aux analyses': 'Back to analyses',
  'Chargement du rapport...': 'Loading the report...',
  "Échec de l'analyse": 'Analysis failed',
  'Rapport indisponible': 'Report unavailable',

  // --- Tableau de bord
  'Score de sécurité': 'Security score',
  'Moyenne pondérée des statuts des actifs': 'Weighted average of the asset statuses',
  'Ce qui pèse le plus': 'What weighs most',
  'Voir ces actifs': 'See these assets',
  ['Le score est la moyenne des statuts des actifs : traiter les lignes du haut le fait remonter le plus '
    + 'vite.']:
    'The score is the average of the asset statuses: dealing with the top rows raises it fastest.',
  'Aucun actif ne pèse sur le score : tous sont recommandés par la politique.':
    'No asset weighs on the score: the policy recommends them all.',
  'Aucun actif cryptographique détecté : le score reste à 100.':
    'No cryptographic asset found: the score stays at 100.',
  'actifs interdits': 'disallowed assets',
  'actif interdit': 'disallowed asset',
  'actifs dépréciés': 'deprecated assets',
  'actif déprécié': 'deprecated asset',
  'actifs de statut inconnu': 'assets of unknown status',
  'actif de statut inconnu': 'asset of unknown status',
  'actifs acceptables mais vulnérables au quantique': 'acceptable assets but quantum-vulnerable',
  'actif acceptable mais vulnérable au quantique': 'acceptable asset but quantum-vulnerable',
  'actifs acceptables': 'acceptable assets',
  'actif acceptable': 'acceptable asset',
  'actifs cryptographiques': 'cryptographic assets',
  'emplacements dans le code': 'locations in the code',
  interdits: 'disallowed',
  dépréciés: 'deprecated',
  'vulnérables au quantique': 'quantum-vulnerable',
  'Vulnérables au quantique': 'Quantum-vulnerable',
  'Vulnérable au quantique': 'Quantum-vulnerable',
  'CVE sur les dépendances': 'CVEs on dependencies',
  'CVE exploitées (KEV)': 'Exploited CVEs (KEV)',
  'constats de sécurité': 'security findings',
  'Conformité à la politique': 'Policy compliance',
  'Primitives utilisées': 'Primitives used',
  'Langages (emplacements)': 'Languages (locations)',
  'Licences des dépendances': 'Dependency licences',
  'À traiter en priorité': 'Deal with these first',
  'Aucun actif interdit ou déprécié.': 'No disallowed or deprecated asset.',
  'Aucun secret, contournement TLS ou aléa faible détecté.':
    'No secret, TLS bypass or weak randomness found.',
  'Pas de dépendances (cdxgen non exécuté).': 'No dependencies (cdxgen was not run).',
  'Copyleft fort : incompatible avec une diffusion propriétaire sans publication du':
    'Strong copyleft: incompatible with proprietary distribution without publishing the',
  "code. Inconnue : vérifier les droits d'usage.": 'code. Unknown: check the usage rights.',
  Avertissements: 'Warnings',
  'Préparation post-quantique': 'Post-quantum readiness',
  'Post-quantique': 'Post-quantum',
  'Asymétrique vulnérable (Shor)': 'Public-key, vulnerable (Shor)',
  'Post-quantique ou hybride': 'Post-quantum or hybrid',
  'Symétrique < 256 bits': 'Symmetric < 256 bits',
  'Non calculé.': 'Not computed.',
  'modules détectés': 'modules found',
  'module détecté': 'module found',
  '(parcours récursif)': '(recursive walk)',
  '- dépôt Git': '- Git repository',

  // --- Actifs
  'Rechercher (nom, fichier, fonction)...': 'Search (name, file, function)...',
  Rechercher: 'Search',
  'Tous les statuts': 'All statuses',
  'Toutes les primitives': 'All primitives',
  'Tous les langages': 'All languages',
  'Toutes origines': 'All origins',
  'Réinitialiser les filtres': 'Reset the filters',
  'Trier par': 'Sort by',
  'Tri : risque': 'Sort: risk',
  'Tri : nom': 'Sort: name',
  'Tri : emplacements': 'Sort: locations',
  'Tri : gravité': 'Sort: severity',
  'Tri : catégorie': 'Sort: category',
  'Tri : fichier': 'Sort: file',
  Actif: 'Asset',
  'Type / primitive': 'Type / primitive',
  Emplacements: 'Locations',
  Emplacement: 'Location',
  Sources: 'Sources',
  Statut: 'Status',
  Type: 'Type',
  'Nom dans le code': 'Name in the code',
  'Taille de clé': 'Key size',
  Mode: 'Mode',
  Bourrage: 'Padding',
  Courbe: 'Curve',
  Opérations: 'Operations',
  Sujet: 'Subject',
  Émetteur: 'Issuer',
  Expiration: 'Expiry',
  'Valide jusqu\'en': 'Valid until',
  'Recommandation :': 'Recommendation:',
  'Voir dans le graphe': 'See in the graph',
  'Sélectionnez un actif pour voir le détail.': 'Select an asset to see its details.',
  'Aucun actif ne correspond aux filtres.': 'No asset matches the filters.',
  'Aucun emplacement : actif déclaré dans le CBOM de cdxgen sans localisation.':
    'No location: asset declared in the cdxgen CBOM without any location.',

  // --- Constats de sécurité
  'Rechercher (titre, fichier, règle)...': 'Search (title, file, rule)...',
  'Toutes gravités': 'All severities',
  'Toutes catégories': 'All categories',
  'Inclure le code de test': 'Include test code',
  Gravité: 'Severity',
  Sévérité: 'Severity',
  Constat: 'Finding',
  'Risque et correction': 'Risk and fix',
  'Élément :': 'Element:',
  'Afficher cet emplacement dans le graphe': 'Show this location in the graph',
  'Aucun constat ne correspond aux filtres.': 'No finding matches the filters.',
  ["Aucun constat : pas de secret en clair, de validation TLS désactivée, d'aléa faible, de clé en dur ni "
    + 'de suite TLS obsolète détectés.']:
    'No finding: no plaintext secret, disabled TLS validation, weak randomness, hardcoded key or outdated '
    + 'TLS cipher suite was found.',
  'Les secrets sont caviardés dans le rapport. Un faux positif peut être ignoré en ajoutant':
    'Secrets are redacted in the report. A false positive can be ignored by adding',
  'le commentaire "chiffrium:ignore" sur la ligne concernée.':
    'the comment "chiffrium:ignore" on the line concerned.',
  'code de test': 'test code',

  // --- Graphe
  'Chercher dans le graphe': 'Search in the graph',
  'Chercher une fonction, un fichier, un algorithme...': 'Search for a function, a file, an algorithm...',
  Chercher: 'Search',
  'Résultat suivant': 'Next result',
  'Repérer un actif dans le graphe': 'Locate an asset in the graph',
  'Tout le graphe': 'Whole graph',
  'Masquer les API externes': 'Hide external APIs',
  'Fonction du projet': 'Project function',
  'API cryptographique': 'Cryptographic API',
  'Fichier de clé': 'Key file',
  'Actif (couleur = statut)': 'Asset (colour = status)',
  "Ce nœud n'a aucun lien connu (détection par règle, sans analyse de flux).":
    'This node has no known link (rule-based detection, without flow analysis).',
  "Chercher ou choisir un actif ne réduit pas le graphe : l'élément est sélectionné et agrandi à sa place,":
    'Searching or picking an asset does not shrink the graph: the item is selected and zoomed in place,',
  'avec ses liens. "Tout le graphe" remet la vue d\'ensemble, sans tout recalculer.':
    'with its links. "Whole graph" restores the overview, without recomputing anything.',
  ['Flèches pleines : utilisation, écriture/lecture de fichiers. Pointillés : appels (analyse de flux '
    + 'cdxgen).']:
    'Solid arrows: usage, file reads and writes. Dashed: calls (cdxgen flow analysis).',
  'Cliquer sur un actif ouvre son détail. Molette : zoom ; glisser : déplacer.':
    'Clicking an asset opens its details. Wheel: zoom; drag: pan.',
  'Au clavier : Tab pour entrer dans le graphe, les flèches gauche et droite pour parcourir les nœuds,':
    'With the keyboard: Tab to enter the graph, left and right arrows to walk the nodes,',
  'les flèches haut et bas pour suivre les liens, Entrée pour ouvrir un actif, Échap pour sortir.':
    'up and down arrows to follow the links, Enter to open an asset, Escape to leave.',
  'Le nœud atteint est décrit sous le graphe.': 'The node reached is described below the graph.',
  'haut et bas pour suivre les liens, Entrée pour ouvrir un actif, Échap pour sortir.':
    'up and down to follow the links, Enter to open an asset, Escape to leave.',

  // --- Dépendances
  Dépendance: 'Dependency',
  Version: 'Version',
  Portée: 'Scope',
  Licence: 'Licence',
  Crypto: 'Crypto',
  Vulnérabilités: 'Vulnerabilities',
  'Aucune dépendance': 'No dependency',
  'non déclarée': 'not declared',
  'Catalogue CISA KEV': 'CISA KEV catalog',
  "Probabilité d'exploitation à 30 jours (EPSS)": 'Probability of exploitation within 30 days (EPSS)',
  ['Aucune dépendance déclarée trouvée. Les outils de build (Maven, Gradle, sbt...) ne sont pas lancés, '
    + 'pour ne pas exécuter le code analysé : les dépendances sont lues dans les pom.xml, les fichiers '
    + 'Gradle (verrous, catalogue, déclarations littérales) et les fichiers de verrouillage npm ou Python. '
    + "Une dépendance calculée par un script de build n'est pas vue."]:
    'No declared dependency found. Build tools (Maven, Gradle, sbt...) are never run, so that the analysed '
    + 'code is not executed: dependencies are read from pom.xml files, Gradle files (locks, catalog, '
    + 'literal declarations) and npm or Python lock files. A dependency computed by a build script is not '
    + 'seen.',

  // --- Étapes et journal
  Étapes: 'Steps',
  Étape: 'Step',
  Résultat: 'Result',
  Détail: 'Detail',
  Durée: 'Duration',
  Journal: 'Log',
  'Journal (.log)': 'Log (.log)',
  'Chargement du journal...': 'Loading the log...',
  '(journal vide)': '(empty log)',
  'Journal copié.': 'Log copied.',
  Copier: 'Copy',
  'Télécharger (.log)': 'Download (.log)',
  Réussie: 'Succeeded',
  Échec: 'Failed',
  Ignorée: 'Skipped',
  'Actualisation automatique': 'Refreshing automatically',
  "En attente d'un emplacement libre (analyses simultanées limitées).":
    'Waiting for a free slot (the number of simultaneous analyses is limited).',
  "Arrêter l'analyse": 'Stop the analysis',
  'Arrêt en cours...': 'Stopping...',
  'arrêt en cours': 'stopping',
  'Arrêter cette analyse ? Elle pourra être relancée depuis la liste des analyses.':
    'Stop this analysis? You can start it again from the analyses list.',
  ["Les traitements en cours sont interrompus et les fichiers temporaires supprimés. Pendant un clonage, "
    + "l'arrêt peut prendre jusqu'à une minute."]:
    'Work in progress is interrupted and temporary files are deleted. During a clone, stopping can take up '
    + 'to a minute.',
  "Arrêt demandé : l'analyse s'interrompt (jusqu'à une minute pendant un clonage).":
    'Stop requested: the analysis is winding down (up to a minute during a clone).',
  'Sur ce dépôt': 'On this repository',
  'Sur les analyses précédentes': 'Across previous analyses',

  // --- Exports
  'Télécharger le CBOM (CycloneDX 1.6)': 'Download the CBOM (CycloneDX 1.6)',
  'Tout télécharger (ZIP)': 'Download everything (ZIP)',
  'Rapport complet (JSON)': 'Full report (JSON)',
  'SARIF (revue de code)': 'SARIF (code review)',
  'Imprimer / PDF': 'Print / PDF',
  'Feuille de revue : score, priorités, constats': 'Review sheet: score, priorities, findings',
  'Comparer avec...': 'Compare with...',
  'Comparer avec une autre analyse du même dépôt': 'Compare with another analysis of the same repository',

  // --- Feuille imprimable
  'Rapport cryptographique': 'Cryptographic report',
  'Chiffrium - inventaire des usages cryptographiques et préparation post-quantique.':
    'Chiffrium - inventory of cryptographic usage and post-quantum readiness.',
  Élément: 'Item',
  Valeur: 'Value',
  Cible: 'Target',
  Branche: 'Branch',
  Commit: 'Commit',
  Analyse: 'Analysis',
  'Éditée le': 'Issued on',
  Outils: 'Tools',
  'Score et priorités': 'Score and priorities',
  '- moyenne pondérée des statuts des actifs cryptographiques.':
    '- weighted average of the cryptographic asset statuses.',
  Nombre: 'Count',
  Coût: 'Cost',
  'Principaux algorithmes': 'Main algorithms',
  'Aucun actif ne pèse sur le score.': 'No asset weighs on the score.',
  Indicateurs: 'Indicators',
  Indicateur: 'Indicator',
  'Actifs cryptographiques': 'Cryptographic assets',
  'Emplacements dans le code': 'Locations in the code',
  Interdits: 'Disallowed',
  Dépréciés: 'Deprecated',
  'Dépendances inventoriées': 'Dependencies inventoried',
  'Vulnérabilités connues (CVE)': 'Known vulnerabilities (CVEs)',
  'dont activement exploitées (KEV)': 'of which actively exploited (KEV)',
  'Actifs cassés par un ordinateur quantique (Shor)': 'Assets broken by a quantum computer (Shor)',
  'Actifs déjà post-quantiques': 'Assets already post-quantum',
  'Chiffrements symétriques sous 256 bits (Grover, CNSA 2.0)':
    'Symmetric ciphers below 256 bits (Grover, CNSA 2.0)',
  Part: 'Share',
  'Correction attendue': 'Expected fix',
  'Dépendances vulnérables': 'Vulnerable dependencies',
  '- exploitée (KEV)': '- exploited (KEV)',
  'Aucun constat.': 'No finding.',
  'Aucune dépendance inventoriée.': 'No dependency inventoried.',
  ["Analyse statique : elle voit où le code crée ses clés, pas leur valeur ni ce qui se décide à "
    + "l'exécution (configuration, coffre), ni les dépendances calculées par un script de build. Les "
    + 'constats sont à confirmer en revue.']:
    'Static analysis: it sees where the code creates its keys, not their value nor what is decided at '
    + 'runtime (configuration, vault), nor dependencies computed by a build script. Findings are to be '
    + 'confirmed in review.',
  ["Clé créée par le code ou l'outillage du dépôt (script, infrastructure, KMS) : sa valeur n'est pas dans le "
    + "dépôt, seuls son algorithme et l'endroit où sa création est décrite sont connus."]:
    'Key created by the code or the tooling of the repository (script, infrastructure, KMS): its value is not '
    + 'in the repository, only its algorithm and the place where its creation is described are known.',

  // --- Comparaison
  'Comparaison en cours...': 'Comparing...',
  'score de sécurité': 'security score',
  'constats corrigés': 'findings fixed',
  'nouvelles vulnérabilités': 'new vulnerabilities',
  'Actifs apparus': 'Assets that appeared',
  'Actifs disparus': 'Assets that disappeared',
  'Changements de statut des actifs': 'Asset status changes',
  'Nouveaux constats de sécurité': 'New security findings',
  'Constats corrigés': 'Findings fixed',
  'Vulnérabilités apparues': 'Vulnerabilities that appeared',
  'Vulnérabilités corrigées': 'Vulnerabilities fixed',
  'Aucun changement de statut.': 'No status change.',
  'Aucun nouveau constat.': 'No new finding.',
  'Aucun constat corrigé.': 'No finding fixed.',
  'Aucun.': 'None.',
  'Aucune.': 'None.',
};
