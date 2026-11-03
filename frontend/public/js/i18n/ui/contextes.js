// Surcharges par écran : quelques mots français se traduisent différemment selon l'endroit.
//
// "Identifiant" est un nom de compte dans Analyses et Administration, mais l'identifiant technique d'un
// algorithme dans le Catalogue. "Actif" est un actif cryptographique dans un rapport, et l'état d'un compte
// dans Administration. La table générale ne peut pas trancher : la page, si.
//
// La clé de premier niveau est la page du routeur (le fragment d'URL : #/catalog -> catalog).

export const CONTEXTES_EN = {
  catalog: {
    Identifiant: 'Identifier',
    'En attente': 'Pending',
    Actif: 'Algorithm',
    Statut: 'Status',
  },
  admin: {
    Actif: 'Active',
    'En attente': 'Pending',
  },
  me: {
    'En attente': 'Pending',
    Connexion: 'Sign-in',
    Demande: 'Request',
  },
  groups: {
    'En attente': 'Pending',
  },
};
