// Dictionnaire de l'interface, français -> anglais, assemblé à partir des zones de l'application.
//
// Une clé est le texte français exact tel qu'il est écrit dans la vue (concaténations comprises). Les zones
// ne doivent pas se contredire : le test frontend/tests/i18n.test.mjs échoue si une même clé reçoit deux
// traductions différentes.

import { ADMINISTRATION } from './ui/administration.js';
import { AIDE_COMPTE } from './ui/aide-compte.js';
import { ANALYSES } from './ui/analyses.js';
import { CATALOGUE_GROUPES } from './ui/catalogue-groupes.js';
import { COMMUN } from './ui/commun.js';
import { COMPLEMENTS } from './ui/complements.js';
import { RAPPORT } from './ui/rapport.js';

export const ZONES = Object.freeze({
  commun: COMMUN,
  analyses: ANALYSES,
  rapport: RAPPORT,
  'catalogue et groupes': CATALOGUE_GROUPES,
  administration: ADMINISTRATION,
  'aide et compte': AIDE_COMPTE,
  compléments: COMPLEMENTS,
});

export const UI_EN = Object.freeze(Object.assign({}, ...Object.values(ZONES)));
