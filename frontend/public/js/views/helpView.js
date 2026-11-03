import { STATUSES } from '../domain/labels.js';
import { SCORE_THRESHOLDS } from '../domain/report.js';
import { badge, h, mount } from '../ui/dom.js';

/** Questions fréquentes, regroupées par thème : [identifiant, titre, [[question, réponse...], ...]]. */
const SECTIONS = Object.freeze([
  ['demarrer', 'Démarrer', [
    ['Comment lancer une analyse ?', 'Page Analyses > "Nouvelle analyse" : collez l\'adresse https d\'un dépôt Git (ou '
      + 'le chemin d\'un dossier de votre ordinateur, en mode local), puis "Lancer l\'analyse". Plusieurs cibles, une '
      + 'par ligne, lancent plusieurs analyses.'],
    ['Combien de temps dure une analyse ?', 'De quelques secondes (petit dépôt, sans cdxgen) à plusieurs dizaines de '
      + 'minutes (très gros dépôt comme Bouncy Castle avec cdxgen). La progression s\'affiche dans la liste ; "Suivre" '
      + 'ouvre les étapes et le journal en direct.'],
    ['Puis-je arrêter une analyse ?', 'Oui : bouton "Arrêter" dans la liste ou sur la page de l\'analyse. Une analyse '
      + 'en attente est retirée de la file ; une analyse en cours s\'interrompt (les programmes lancés sont arrêtés, le '
      + 'clone temporaire est supprimé) et passe à l\'état "Arrêtée". Il n\'y a pas de pause : relancez-la ensuite '
      + 'avec "Plus > Relancer l\'analyse", qui reprend les mêmes paramètres.'],
    ['Pourquoi mon analyse reste "En attente" ?', 'Le nombre d\'analyses simultanées est limité (cdxgen est gourmand '
      + 'en mémoire). La position dans la file est indiquée ; elle démarre dès qu\'un emplacement se libère.'],
    ['À quoi sert cdxgen ?', 'Il produit l\'inventaire des dépendances (SBOM) et suit les flux cryptographiques en Java '
      + 'et Python. Sans lui, le moteur de règles (16 langages) s\'exécute seul : plus rapide, mais sans dépendances ni '
      + 'vulnérabilités.'],
  ]],
  ['lire', 'Lire un rapport', [
    ['Que signifie le score ?', `Moyenne des actifs cryptographiques pondérés par leur statut, sur 100 : `
      + `à partir de ${SCORE_THRESHOLDS.good} c'est bon, de ${SCORE_THRESHOLDS.warning} à ${SCORE_THRESHOLDS.good - 1} à `
      + `surveiller, en dessous il faut agir. Un algorithme acceptable mais cassable par un ordinateur quantique est `
      + `pénalisé. Un projet sans cryptographie obtient 100.`],
    ['Que veulent dire les statuts ?', null],
    ['Actifs, constats, dépendances : quelle différence ?', 'Les actifs sont les algorithmes, protocoles, certificats '
      + 'et clés trouvés (le CBOM). Les constats sont des erreurs de sécurité (secret dans le code, validation TLS '
      + 'désactivée, IV fixe...). Les dépendances sont les bibliothèques utilisées, avec leurs vulnérabilités connues '
      + 'et leur licence.'],
    ['Pourquoi "À vérifier" ?', 'L\'algorithme n\'est pas dans le catalogue ou sa taille de clé / son mode n\'a pas pu '
      + 'être déterminé. Ouvrez l\'actif pour voir les occurrences dans le code ; proposez un ajout au catalogue si '
      + 'besoin.'],
    ['Et le post-quantique ?', 'Le tableau de bord indique l\'étape de migration : RSA, ECDSA, DH... seront cassés par un '
      + 'ordinateur quantique ; les remplaçants sont ML-KEM (échange de clés) et ML-DSA / SLH-DSA (signature), '
      + 'souvent en hybride pendant la transition.'],
    ['Comment voir l\'évolution d\'un projet ?', 'Cochez deux analyses terminées du même dépôt dans la liste, puis '
      + '"Comparer" (ou "Comparer avec..." sur la page du rapport) : actifs apparus ou disparus, constats corrigés, '
      + 'nouvelles vulnérabilités.'],
  ]],
  ['fichiers', 'Fichiers téléchargeables', [
    ['CBOM (CycloneDX 1.6, .json)', 'L\'inventaire cryptographique standard, lisible par d\'autres outils (Dependency-'
      + 'Track, plateformes de conformité).'],
    ['Rapport complet (.json)', 'Tout ce qu\'affiche l\'interface : actifs, constats, dépendances, graphe, étapes.'],
    ['SARIF (.sarif)', 'Format des outils d\'analyse de code : s\'importe dans GitHub, GitLab, Azure DevOps ou '
      + 'SonarQube pour afficher les constats dans les revues de code.'],
    ['Journal (.log)', 'Le déroulé technique de l\'analyse, utile en cas d\'échec.'],
    ['Tout télécharger (.zip)', 'Les quatre fichiers ci-dessus dans une seule archive.'],
  ]],
  ['equipe', 'Travailler en équipe', [
    ['Qui voit mes analyses ?', 'Une analyse privée n\'est visible que de vous et des administrateurs. Partagée avec '
      + 'un groupe, elle est visible de ses membres. Changez la visibilité à tout moment ("Plus").'],
    ['Comment rejoindre un groupe ?', 'Page Groupes : acceptez une invitation reçue, ou demandez à rejoindre un groupe '
      + 'public (un responsable accepte). Vous pouvez quitter un groupe à tout moment.'],
    ['Comment faire changer le classement d\'un algorithme ?', 'Page Catalogue : ouvrez l\'algorithme puis "Proposer '
      + 'une modification" (ou "Proposer un algorithme" s\'il manque). Un administrateur accepte ou refuse avec un '
      + 'motif ; la décision vous est notifiée et tracée.'],
    ['Où sont mes notifications ?', 'La cloche en haut de page ; l\'historique complet est dans "Mon espace" (clic sur '
      + 'votre nom).'],
  ]],
  ['donnees', 'Données et espace disque', [
    ['Où sont stockées les données ?', 'En mode local, dans votre profil (%APPDATA%\\Chiffrium sous Windows), '
      + 'base et rapports chiffrés. En mode équipe, sur le serveur de l\'équipe.'],
    ['Les clones Git remplissent-ils le disque ?', 'Non : chaque clone est temporaire et supprimé à la fin de '
      + 'l\'analyse, même en cas d\'échec ou d\'arrêt. Les restes éventuels (arrêt brutal) sont nettoyés au démarrage et '
      + 'toutes les heures ; Administration > Stockage permet aussi de le faire à la main.'],
    ['Et les rapports ?', 'Ils sont conservés selon la politique de rétention (Administration > Paramètres > '
      + 'Conservation) ; supprimez une analyse avec "Plus > Supprimer".'],
    ['Comment mettre à jour l\'application ?', 'Quand une nouvelle version est disponible, elle se télécharge en arrière-'
      + 'plan puis un bouton "Mettre à jour" apparaît en haut de la fenêtre (ou menu Aide > Rechercher des mises à '
      + 'jour). Si des analyses tournent, choisissez de l\'installer à la fin des analyses, tout de suite (elles '
      + 'reprendront après le redémarrage) ou à la fermeture de l\'application.'],
    ['Que devient une analyse si je ferme l\'application ?', 'Une confirmation est demandée ; l\'analyse est interrompue '
      + 'puis reprend automatiquement depuis le début au prochain lancement. Seul un arrêt brutal (plantage, coupure) '
      + 'la marque en échec : relancez-la avec "Plus > Relancer l\'analyse".'],
    ['Quelles informations sortent de mon ordinateur ?', 'Le clonage des dépôts demandés et, si activées, les requêtes '
      + 'aux bases de vulnérabilités (noms et versions de dépendances, jamais le code). La liste exacte est sur la page '
      + 'À propos.'],
  ]],
]);

/** Page d'aide : premiers pas, lecture des rapports, formats, travail en équipe, données. */
export function renderHelp(container) {
  const statusList = h('ul', { class: 'bar-list' }, STATUSES.map((s) => h('li', {}, badge(s), ' ',
    h('span', { class: 'muted small' }, STATUS_HELP[s.id]))));
  mount(container, h('div', { class: 'help-page' },
    h('section', { class: 'card' },
      h('h1', {}, 'Aide'),
      h('p', { class: 'muted' }, 'Chiffrium inventorie la cryptographie d\'un projet (algorithmes, clés, certificats, '
        + 'protocoles), la compare à une politique (le catalogue), signale les erreurs de sécurité et prépare la '
        + 'migration post-quantique.'),
      h('ul', { class: 'help-toc' }, SECTIONS.map(([id, title]) => h('li', {},
        h('a', { href: `#/help`, onclick: (e) => { e.preventDefault(); document.getElementById(`aide-${id}`)
          ?.scrollIntoView({ behavior: 'smooth' }); } }, title))))),
    SECTIONS.map(([id, title, entries]) => h('section', { class: 'card', id: `aide-${id}` },
      h('h2', {}, title),
      h('dl', {}, entries.map(([question, answer]) => [
        h('dt', {}, question),
        h('dd', {}, answer ?? statusList)]))))));
}

const STATUS_HELP = Object.freeze({
  recommended: 'conforme à l\'état de l\'art (ex. AES-256-GCM, SHA-256, ML-KEM)',
  acceptable: 'encore sûr aujourd\'hui, à suivre (ex. RSA-3072, souvent vulnérable au quantique)',
  unknown: 'information insuffisante pour trancher (algorithme absent du catalogue, taille de clé inconnue)',
  deprecated: 'affaibli, à remplacer (ex. SHA-1 pour la signature, RSA-1024, TLS 1.0)',
  disallowed: 'cassé ou interdit par la politique (ex. MD5, DES, RC4)',
});
