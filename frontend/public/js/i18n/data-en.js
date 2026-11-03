// Textes livrés par le serveur : règles de détection et catalogue d'algorithmes.
//
// Ces phrases sont écrites dans backend/src/main/resources ; elles arrivent telles quelles dans l'interface,
// donc elles se traduisent comme le reste. Le test frontend/tests/i18n.test.mjs échoue si l'une d'elles
// manque : ajouter une règle ou une entrée de catalogue impose d'ajouter sa traduction.
//
// Le catalogue est découpé en deux fichiers pour rester lisible ; l'ordre suit celui de l'original.

import { CATALOGUE_A } from './data/catalogue-a.js';
import { CATALOGUE_B } from './data/catalogue-b.js';
import { REGLES } from './data/regles.js';

export const DATA_EN = Object.freeze({ ...REGLES, ...CATALOGUE_A, ...CATALOGUE_B });
