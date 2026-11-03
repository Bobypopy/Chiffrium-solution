// Catalogue d'algorithmes (politique) et groupes de travail.

export const CATALOGUE_GROUPES = {
  // --- Catalogue : liste et filtres
  'Chargement du catalogue...': 'Loading the catalog...',
  'Algorithmes et protocoles': 'Algorithms and protocols',
  Algorithmes: 'Algorithms',
  Protocoles: 'Protocols',
  Algorithme: 'Algorithm',
  Famille: 'Family',
  Primitive: 'Primitive',
  Quantique: 'Quantum',
  Validité: 'Validity',
  Note: 'Note',
  Recommandation: 'Recommendation',
  Actions: 'Actions',
  État: 'State',
  'Filtrer le catalogue': 'Filter the catalog',
  'Filtrer (nom, alias, OID, mot-clé de la note)...': 'Filter (name, alias, OID, keyword from the note)...',
  'Tous les statuts': 'All statuses',
  'Toutes les familles': 'All families',
  'Quantique : tous': 'Quantum: all',
  'Cassés par Shor': 'Broken by Shor',
  'Résistants (post-quantique)': 'Resistant (post-quantum)',
  'Symétriques (marge Grover)': 'Symmetric (Grover margin)',
  'Déjà à proscrire': 'Already to be avoided',
  'Aucune entrée ne correspond aux filtres.': 'No entry matches the filters.',
  'Cassé par un ordinateur quantique (algorithme de Shor : RSA, Diffie-Hellman, courbes elliptiques)':
    'Broken by a quantum computer (Shor algorithm: RSA, Diffie-Hellman, elliptic curves)',
  "Source de vérité pour la détection (alias) et l'évaluation (statuts, années de":
    'Single source of truth for detection (aliases) and evaluation (statuses, NIST',
  'transition NIST, tailles de clé, résistance quantique). Modes, bourrages et courbes :':
    'transition years, key sizes, quantum resistance). Modes, paddings and curves:',

  // --- Catalogue : édition
  'Ajouter un algorithme': 'Add an algorithm',
  'Nouvel algorithme': 'New algorithm',
  Modifier: 'Edit',
  Enregistrer: 'Save',
  Supprimer: 'Delete',
  Annuler: 'Cancel',
  'Nom affiché': 'Display name',
  'Alias de détection': 'Detection aliases',
  'formes compactes en minuscules, ex. sha256, sha2256': 'compact lowercase forms, e.g. sha256, sha2256',
  'Déprécié après (année)': 'Deprecated after (year)',
  'Interdit après (année)': 'Disallowed after (year)',
  'ex. 2.16.840.1.101.3.4.2.1': 'e.g. 2.16.840.1.101.3.4.2.1',
  "Aucun OID. Les protocoles et certains algorithmes n'en ont pas.":
    'No OID. Protocols and some algorithms do not have one.',
  'Chercher sur oid-base.com': 'Search on oid-base.com',
  'Vérifier :': 'Check:',

  // --- Catalogue : politique partagée
  'Politique d\'entreprise': 'Company policy',
  'Publier la politique': 'Publish the policy',
  "Figer le catalogue actuel comme politique d'entreprise, à diffuser aux autres installations":
    'Freeze the current catalog as the company policy, to hand to other installations',
  'Nom de la politique à publier :': 'Name of the policy to publish:',
  ['Catalogue local : aucune politique publiée. "Publier la politique" fige une version numérotée, '
    + 'exportable vers les autres installations.']:
    'Local catalog: no policy published. "Publish the policy" freezes a numbered version that can be '
    + 'exported to other installations.',
  Exporter: 'Export',
  Importer: 'Import',
  'Catalogue importé.': 'Catalog imported.',
  'Fichier JSON invalide.': 'Invalid JSON file.',
  'Fichier trop volumineux.': 'File too large.',
  "Fichier sans politique publiée (export d'un catalogue local).":
    'File without a published policy (export of a local catalog).',
  'Contenu identique au catalogue actuel.': 'Content identical to the current catalog.',
  'Une sauvegarde de la version précédente est conservée par le serveur.':
    'The server keeps a backup of the previous version.',

  // --- Catalogue : propositions
  'Proposer un algorithme': 'Propose an algorithm',
  'Proposer un nouvel algorithme': 'Propose a new algorithm',
  'Proposer une modification': 'Propose a change',
  'Proposer le retrait': 'Propose removal',
  'Mes demandes': 'My requests',
  Demande: 'Request',
  'Envoyer la demande': 'Send the request',
  'Demande envoyée aux administrateurs.': 'Request sent to the administrators.',
  'Aucune demande pour le moment.': 'No request for now.',
  Justification: 'Justification',
  'Pourquoi ce changement ? (référence normative, décision interne, besoin métier...)':
    'Why this change? (standards reference, internal decision, business need...)',
  'Au nom du groupe': 'On behalf of the group',
  'Votre proposition sera examinée par un administrateur ; vous serez':
    'Your proposal will be reviewed by an administrator; you will be',
  'informé de sa décision dans "Mes demandes".': 'told the decision in "My requests".',
  Accepter: 'Approve',
  Refuser: 'Reject',
  Acceptée: 'Approved',
  Refusée: 'Rejected',
  Retirée: 'Withdrawn',
  Retirer: 'Withdraw',
  'Motif du refus (communiqué au demandeur) :': 'Reason for rejection (sent to the requester):',
  'Commentaire (facultatif) :': 'Comment (optional):',
  Ajout: 'Addition',
  'Ajout manuel': 'Manual addition',
  Modification: 'Change',
  Retrait: 'Removal',

  // --- Groupes
  'Mes groupes': 'My groups',
  'Autres groupes': 'Other groups',
  'Annuaire des groupes publics': 'Directory of public groups',
  'Créer un groupe': 'Create a group',
  Créer: 'Create',
  Groupe: 'Group',
  'Nom du groupe': 'Group name',
  Nom: 'Name',
  Description: 'Description',
  Visibilité: 'Visibility',
  Privé: 'Private',
  Public: 'Public',
  "visible de ses seuls membres, on y entre sur invitation":
    'visible to its members only, you join by invitation',
  "visible dans l'annuaire, chacun peut demander à le rejoindre":
    'listed in the directory, anyone can ask to join',
  'Modifier le groupe': 'Edit the group',
  'Groupe créé : vous en êtes responsable.': 'Group created: you are its manager.',
  'Groupe mis à jour.': 'Group updated.',
  Membres: 'Members',
  Membre: 'Member',
  Responsable: 'Manager',
  Rôle: 'Role',
  Quitter: 'Leave',
  'Inviter un utilisateur': 'Invite a user',
  Inviter: 'Invite',
  'Identifiant à inviter': 'Username to invite',
  'Identifiant du compte': 'Account username',
  'Message (facultatif)': 'Message (optional)',
  'Demander à rejoindre': 'Ask to join',
  'Demande envoyée': 'Request sent',
  'Demande envoyée aux responsables.': 'Request sent to the managers.',
  'Demande annulée.': 'Request cancelled.',
  'Demande refusée.': 'Request rejected.',
  "Annuler l'invitation": 'Cancel the invitation',
  'Invitation annulée.': 'Invitation cancelled.',
  'Invitation déclinée.': 'Invitation declined.',
  'Invitations en attente de réponse :': 'Invitations awaiting an answer:',
  "Vous n'appartenez à aucun groupe. Rejoignez un groupe public ou attendez une invitation.":
    'You do not belong to any group. Join a public group or wait for an invitation.',
  'Aucun autre groupe visible.': 'No other visible group.',
  'Les analyses rattachées à un groupe sont visibles de ses membres. Les responsables':
    'Analyses attached to a group are visible to its members. Managers',
  'invitent, acceptent les demandes, retirent des membres et peuvent supprimer les analyses du groupe.':
    'invite, accept requests, remove members and can delete the analyses of the group.',

  // --- Synthèse de groupe
  'score moyen': 'average score',
  'dépôt suivi': 'repository tracked',
  'dépôts suivis': 'repositories tracked',
  'Dépôts, du plus exposé au moins exposé': 'Repositories, most exposed first',
  Dépôt: 'Repository',
  Évolution: 'Change',
  'Pas encore de deuxième analyse : la progression apparaîtra ensuite':
    'No second analysis yet: progress will show up afterwards',
  ['Aucune analyse terminée rattachée à ce groupe : rattachez une analyse au groupe depuis sa page pour '
    + 'alimenter cette synthèse.']:
    'No finished analysis attached to this group: attach an analysis to the group from its page to feed '
    + 'this summary.',
};
