// Traduction de l'interface : mécanique, cohérence des tables, couverture des textes du serveur.
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { test } from 'node:test';

import { locale, missing, setContext, setLocale, t } from '../public/js/i18n.js';
import { DATA_EN } from '../public/js/i18n/data-en.js';
import { PATTERNS_EN } from '../public/js/i18n/patterns-en.js';
import { UI_EN, ZONES } from '../public/js/i18n/ui-en.js';

const RESSOURCES = '../../backend/src/main/resources';
/** Champs des données du serveur qui arrivent tels quels dans l'interface. */
const CHAMPS = ['title', 'description', 'recommendation', 'note'];

function textesDuServeur(chemin) {
  const trouves = new Set();
  const visite = (valeur) => {
    if (Array.isArray(valeur)) valeur.forEach(visite);
    else if (valeur && typeof valeur === 'object') {
      for (const [cle, sous] of Object.entries(valeur)) {
        if (typeof sous === 'string' && CHAMPS.includes(cle) && sous.trim()) trouves.add(sous.trim());
        else visite(sous);
      }
    }
  };
  visite(JSON.parse(readFileSync(new URL(chemin, import.meta.url), 'utf8')));
  return trouves;
}

test('la traduction rend le français quand elle ne connaît pas, et garde les espaces de jointure', () => {
  setLocale('fr', { remember: false });
  assert.equal(locale(), 'fr');
  assert.equal(t('Analyses'), 'Analyses', 'en français, rien ne change');

  setLocale('en', { remember: false });
  assert.equal(t('Analyses'), 'Analyses');
  assert.equal(t('Catalogue'), 'Catalog');
  // Les vues découpent les phrases : l'espace de jointure doit survivre à la traduction.
  assert.equal(t('Déconnexion '), 'Sign out ');
  assert.equal(t(' Déconnexion'), ' Sign out');
  // Une donnée (chemin, identifiant) traverse sans être touchée.
  assert.equal(t('src/main/java/Crypto.java'), 'src/main/java/Crypto.java');
  assert.equal(t('Texte français jamais traduit ici'), 'Texte français jamais traduit ici');
});

test('quelques mots dépendent de l\'écran', () => {
  setLocale('en', { remember: false });
  setContext('analyses');
  assert.equal(t('Identifiant'), 'Username');
  setContext('catalog');
  assert.equal(t('Identifiant'), 'Identifier', 'dans le catalogue, c\'est l\'identifiant d\'un algorithme');
  setContext('admin');
  assert.equal(t('Actif'), 'Active', 'en administration, c\'est l\'état d\'un compte');
  setContext(null);
  assert.equal(t('Actif'), 'Asset');
});

test('les phrases construites avec des valeurs sont reconnues', () => {
  setLocale('en', { remember: false });
  setContext(null);
  const cas = [
    ['Autres actions pour bc-java', 'Other actions for bc-java'],
    ['15 étape(s)', '15 steps'],
    ['1 étape(s)', '1 step'],
    ['Rôle de admin', 'Role of admin'],
    ['Chaîne intègre (304 entrées)', 'Chain intact (304 entries)'],
    ['3 résultats pour "ecdsa", sélectionnés dans le graphe.', '3 results for "ecdsa", selected in the graph.'],
    ['Mon espace - admin - rôle admin', 'My space - admin - role admin'],
    ['Analyse terminée : config-demo', 'Analysis finished: config-demo'],
    ['Interdit par la politique interne dès 2026', 'Disallowed by the internal policy from 2026'],
    ['Clé privée RSA-2048 générée (Keys.java)', 'Private key RSA-2048 generated (Keys.java)'],
    ['Clé générée, algorithme non déterminé (keys.js)', 'Key generated, algorithm not determined (keys.js)'],
    ['Clé privée générée, algorithme non déterminé (A.java)',
      'Private key generated, algorithm not determined (A.java)'],
    ['Clé non identifiée (legacy.key)', 'Unidentified key (legacy.key)'],
    ['Hôte Git non autorisé : gitlab.com (autorisés : [github.com]).',
      'Git host not allowed: gitlab.com (allowed: [github.com]).'],
  ];
  for (const [francais, anglais] of cas) assert.equal(t(francais), anglais, francais);
});

test('les tables ne se contredisent pas et ne contiennent que du texte', () => {
  const vus = new Map();
  const conflits = [];
  for (const [zone, table] of Object.entries(ZONES)) {
    for (const [fr, en] of Object.entries(table)) {
      assert.equal(typeof en, 'string', `${zone} : la traduction de "${fr}" n'est pas un texte`);
      assert.ok(fr.trim() === fr, `${zone} : la clé "${fr}" a un espace en trop`);
      if (vus.has(fr) && vus.get(fr)[1] !== en) conflits.push(`${fr} (${vus.get(fr)[0]} / ${zone})`);
      vus.set(fr, [zone, en]);
    }
  }
  assert.deepEqual(conflits, [], 'deux zones traduisent la même phrase différemment : voir ui/contextes.js');
  assert.ok(Object.keys(UI_EN).length > 700, 'le dictionnaire de l\'interface est trop maigre');
});

test('les motifs sont valides et ne se marchent pas dessus', () => {
  for (const [expression, remplacement] of PATTERNS_EN) {
    assert.ok(expression instanceof RegExp, 'un motif doit être une expression régulière');
    assert.ok(typeof remplacement === 'string' || typeof remplacement === 'function');
    assert.ok(expression.source.startsWith('^') && expression.source.endsWith('$'),
      `le motif ${expression} doit couvrir toute la phrase`);
  }
});

test('tout ce que le serveur affiche a sa traduction', (t) => {
  // L'image Docker du frontend lance ces tests avec le seul dossier frontend/ : les ressources du backend
  // n'y sont pas. Le test tourne en local et dans le job "Frontend (tests)", ou le depot est complet.
  if (!existsSync(new URL(`${RESSOURCES}/findings/`, import.meta.url))) {
    t.skip('ressources du backend absentes de ce contexte de construction');
    return;
  }
  setLocale('en', { remember: false });
  setContext(null);
  const manquants = [];
  const fichiers = readdirSync(new URL(`${RESSOURCES}/findings/`, import.meta.url))
    .filter((f) => f.endsWith('.json') && f !== 'index.json');
  const textes = new Set();
  for (const fichier of fichiers) {
    for (const texte of textesDuServeur(`${RESSOURCES}/findings/${fichier}`)) textes.add(texte);
  }
  for (const texte of textesDuServeur(`${RESSOURCES}/catalog/default-catalog.json`)) textes.add(texte);
  // Un identifiant technique (id-sha256, des-ede3-cbc) n'a pas à être traduit : il n'a ni espace ni mot
  // français.
  const traduisible = (texte) => texte.includes(' ')
    && /[àâäçéèêëîïôöùûüœ]|(le|la|les|des|du|une|un|vous|pour|avec|dans|sur|est|sont|par|ou|et)/i
      .test(texte);
  for (const texte of textes) {
    if (traduisible(texte) && !DATA_EN[texte] && t(texte) === texte) manquants.push(texte);
  }
  assert.deepEqual(manquants.slice(0, 5), [],
    `${manquants.length} texte(s) du serveur sans traduction : ajoutez-les dans i18n/data-en.js`);
});

test('la campagne peut repérer ce qui reste en français', () => {
  setLocale('en', { remember: false });
  missing.clear();
  t('Une phrase française absente du dictionnaire');
  assert.ok(missing.has('Une phrase française absente du dictionnaire'));
  t('deploy/k8s/base/backend.yaml');
  assert.equal(missing.size, 1, 'un chemin de fichier n\'est pas un texte manquant');
});
