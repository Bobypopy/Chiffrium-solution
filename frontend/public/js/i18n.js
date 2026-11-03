// Traduction de l'interface.
//
// Choix d'architecture : les vues restent écrites en français et ne sont pas modifiées. Tout texte passe par
// `h()` (voir ui/dom.js), qui le fait traverser `t()` : une table français -> anglais fournit la traduction.
// Conséquences voulues :
//   - changer de langue ne peut pas casser un écran, puisqu'aucune vue n'a de code de traduction ;
//   - une entrée manquante retombe sur le français, visible et sans erreur ;
//   - les phrases construites avec des valeurs ("3 résultats pour ...") sont traitées par des motifs, faute
//     de pouvoir les retrouver telles quelles dans une table.
//
// Ce qui vient du serveur (titres de constats, catalogue) est traduit de la même façon : ces textes sont
// livrés avec le produit, donc connus à l'avance. Un test vérifie qu'aucun ne manque (voir
// frontend/tests/i18n.test.mjs).

import { CONTEXTES_EN } from './i18n/ui/contextes.js';
import { PATTERNS_EN } from './i18n/patterns-en.js';
import { DATA_EN } from './i18n/data-en.js';
import { UI_EN } from './i18n/ui-en.js';
import { readPref, writePref } from './ui/prefs.js';

export const LOCALES = Object.freeze([
  { id: 'fr', label: 'Français', title: 'Interface en français' },
  { id: 'en', label: 'English', title: 'Switch the interface to English' },
]);
const SECTION = 'locale';
const DEFAULT_LOCALE = 'fr';

const TABLES = { en: { ...UI_EN, ...DATA_EN } };
const PATTERNS = { en: PATTERNS_EN };
const CONTEXTES = { en: CONTEXTES_EN };

let current = DEFAULT_LOCALE;
let table = null;
let patterns = [];
let contexte = null;
const listeners = new Set();
/** Textes non traduits rencontrés : sert aux tests d'interface, jamais à l'affichage. */
export const missing = new Set();

export function locale() {
  return current;
}

// Diagnostic : la campagne de tests parcourt les ecrans en anglais et verifie que cet ensemble reste vide.
if (globalThis.window) globalThis.window.__i18n = { missing, locale, setLocale, t };

/** Langue retenue au premier lancement : celle du navigateur si elle est proposée, sinon le français. */
function preferred() {
  const stored = readPref(SECTION, 'ui', null);
  if (LOCALES.some((l) => l.id === stored)) return stored;
  const navigateur = (globalThis.navigator?.language ?? '').slice(0, 2).toLowerCase();
  return LOCALES.some((l) => l.id === navigateur) ? navigateur : DEFAULT_LOCALE;
}

export function setLocale(next, { remember = true } = {}) {
  current = LOCALES.some((l) => l.id === next) ? next : DEFAULT_LOCALE;
  table = TABLES[current] ?? null;
  patterns = PATTERNS[current] ?? [];
  contexte = null;
  missing.clear();
  if (globalThis.document) document.documentElement.lang = current;
  if (remember) writePref(SECTION, 'ui', current);
  for (const listener of listeners) listener(current);
}

export function initLocale() {
  setLocale(preferred(), { remember: false });
}

/**
 * Écran courant : quelques mots se traduisent différemment selon la page (voir ui/contextes.js).
 * @param {string} page page du routeur (analyses, catalog, admin...)
 */
export function setContext(page) {
  contexte = CONTEXTES[current]?.[page] ?? null;
}

/** Prévient d'un changement de langue (le routeur redessine alors la page courante). */
export function onLocaleChange(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/**
 * Traduit un texte de l'interface.
 *
 * Les espaces de début et de fin sont conservés : les vues découpent les longues phrases en morceaux
 * (`'... puis cliquez sur '`), et ces espaces font la jointure.
 *
 * @param {string} text texte français
 * @returns {string} sa traduction, ou le texte d'origine si elle manque
 */
export function t(text) {
  if (!table || typeof text !== 'string' || !text) return text;
  const noyau = text.trim();
  if (!noyau) return text;
  const traduction = contexte?.[noyau] ?? table[noyau] ?? motif(noyau) ?? prefixe(noyau)
    ?? compose(noyau);
  if (traduction === undefined) {
    // Une chaîne sans lettre accentuée ni mot français est le plus souvent une donnée (chemin, identifiant).
    if (/[àâäçéèêëîïôöùûüœ]|\b(le|la|les|des|une|un|vous|pour|avec|dans|sur|est|sont|aucun|aucune)\b/i.test(noyau)) {
      missing.add(noyau);
    }
    return text;
  }
  const avant = text.slice(0, text.indexOf(noyau[0]));
  const apres = text.slice(text.lastIndexOf(noyau[noyau.length - 1]) + 1);
  return avant + traduction + apres;
}

/**
 * Deux libellés reliés par une flèche ("Migration non commencée -> Transition en cours") : chaque membre se
 * traduit seul, la flèche ne bouge pas.
 */
function compose(texte) {
  if (!texte.includes(' -> ')) return undefined;
  const membres = texte.split(' -> ');
  const traduits = membres.map((membre) => contexte?.[membre] ?? table[membre] ?? motif(membre) ?? membre);
  return traduits.some((traduit, index) => traduit !== membres[index]) ? traduits.join(' -> ') : undefined;
}

/**
 * Une puce ou un séparateur devant un libellé connu : on traduit ce qui suit et on remet le préfixe.
 * L'interface préfixe souvent une valeur ("- Secret exposé", "- le 24/09/2026").
 */
function prefixe(texte) {
  const marque = /^(-|\u2022|\u00b7)\s+/.exec(texte);
  if (!marque) return undefined;
  const reste = texte.slice(marque[0].length);
  const traduit = contexte?.[reste] ?? table[reste] ?? motif(reste);
  return traduit === undefined ? undefined : marque[0] + traduit;
}

/** Phrases construites avec des valeurs : on retrouve la forme, on replace les valeurs. */
function motif(texte) {
  for (const [expression, remplacement] of patterns) {
    const trouve = expression.exec(texte);
    if (trouve) {
      // Le dernier argument traduit un morceau capturé : « (désactivé dans la demande) » doit suivre.
      return typeof remplacement === 'function'
        ? remplacement(...trouve.slice(1), t)
        : remplacement.replace(/\$(\d)/g, (_, index) => trouve[Number(index)] ?? '');
    }
  }
  return undefined;
}
