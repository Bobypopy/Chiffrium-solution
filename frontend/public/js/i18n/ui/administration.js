// Administration : vue d'ensemble, comptes, journal d'audit, paramètres, stockage.

export const ADMINISTRATION = {
  // --- Onglets et vue d'ensemble
  Administration: 'Administration',
  "Vue d'ensemble": 'Overview',
  Utilisateurs: 'Users',
  "Journal d'audit": 'Audit log',
  Paramètres: 'Settings',
  Stockage: 'Storage',
  'Accès réservé aux administrateurs.': 'Administrators only.',
  Activité: 'Activity',
  'À traiter': 'To deal with',
  'Rien à signaler': 'Nothing to report',
  'analyse(s) conservée(s)': 'analysis/analyses kept',
  'en cours / en attente': 'running / queued',
  'analyse(s) en échec (24 h)': 'failed analysis/analyses (24 h)',
  'échec(s) de connexion (24 h)': 'failed sign-in(s) (24 h)',
  'demande(s) au catalogue en attente': 'pending catalog request(s)',
  "demande(s) d'adhésion à un groupe": 'group join request(s)',
  'stockage utilisé': 'storage used',
  'utilisés (pas de quota)': 'used (no quota)',
  'Les notifications (cloche en haut de page) vous préviennent aussi en temps réel ; un':
    'Notifications (the bell at the top) also warn you in real time; a',
  "canal d'équipe gratuit (Slack, Teams, Discord, Mattermost) peut les relayer : voir Paramètres > Alertes.":
    'free team channel (Slack, Teams, Discord, Mattermost) can relay them: see Settings > Alerts.',

  // --- Comptes
  Comptes: 'Accounts',
  Compte: 'Account',
  'Nouvel utilisateur': 'New user',
  Utilisateur: 'User',
  Identifiant: 'Username',
  'Nom affiché': 'Display name',
  'E-mail': 'Email',
  Rôle: 'Role',
  Administrateur: 'Administrator',
  Analyste: 'Analyst',
  Lecteur: 'Viewer',
  État: 'State',
  Désactivé: 'Disabled',
  Verrouillé: 'Locked',
  'Dernière connexion': 'Last sign-in',
  Créer: 'Create',
  'Compte créé.': 'Account created.',
  Désactiver: 'Disable',
  Réactiver: 'Re-enable',
  'Réinitialiser le mot de passe': 'Reset the password',
  'Transmettez-le par un canal sûr : il ne sera plus affiché. L\'utilisateur devra le changer à sa':
    'Pass it on through a safe channel: it will not be shown again. The user will have to change it on their',
  'première connexion.': 'first sign-in.',
  Copier: 'Copy',
  Masquer: 'Hide',

  // --- Journal d'audit
  "Vérifier l'intégrité": 'Check the integrity',
  'Vérification...': 'Checking...',
  Intègre: 'Intact',
  Altéré: 'Tampered with',
  Date: 'Date',
  Action: 'Action',
  'Action (ex. LOGIN_FAILURE)': 'Action (e.g. LOGIN_FAILURE)',
  Objet: 'Object',
  Détail: 'Detail',
  Adresse: 'Address',
  'Aucun événement.': 'No event.',
  'Afficher plus': 'Show more',
  Exporter: 'Export',
  'Archivage à jour': 'Archiving up to date',
  'Archivage en échec': 'Archiving failing',
  '- aucun archivage externe (configurer un dossier ou un collecteur)':
    '- no external archiving (set up a folder or a collector)',
  "- aucun envoi réussi pour l'instant": '- no successful delivery so far',
  ["Archivage externe non configuré : le journal reste uniquement dans la base (voir Paramètres > Journal "
    + "d'audit)."]:
    'External archiving not configured: the log stays in the database only (see Settings > Audit log).',
  "Journal en ajout seul : chaque entrée contient l'empreinte SHA-256 de la précédente,":
    'Append-only log: each entry carries the SHA-256 hash of the previous one,',
  "toute modification ou suppression a posteriori est détectée. Les secrets n'y figurent jamais.":
    'so any later change or deletion is detected. Secrets never appear in it.',

  // --- Paramètres : conservation et sessions
  'Conservation des données': 'Data retention',
  'Rétention (jours, 0 = illimitée)': 'Retention (days, 0 = unlimited)',
  'Rétention illimitée.': 'Unlimited retention.',
  'Volume maximal (Mo, 0 = illimité)': 'Maximum volume (MB, 0 = unlimited)',
  'Au-delà, les analyses les plus anciennes sont purgées.': 'Beyond that, the oldest analyses are purged.',
  'Conserver les sorties brutes de cdxgen (chiffrées ; volumineuses)':
    'Keep the raw cdxgen output (encrypted; bulky)',
  Sessions: 'Sessions',
  'Expiration après inactivité (min)': 'Expiry after inactivity (min)',
  'Durée maximale (h)': 'Maximum duration (h)',

  // --- Paramètres : sources de vulnérabilités
  'Sources de vulnérabilités': 'Vulnerability sources',
  'OSV (dépendances, sans clé)': 'OSV (dependencies, no key needed)',
  'CISA KEV (vulnérabilités exploitées)': 'CISA KEV (exploited vulnerabilities)',
  "EPSS (probabilité d'exploitation)": 'EPSS (probability of exploitation)',
  'NVD (score CVSS officiel)': 'NVD (official CVSS score)',
  "Clé d'API NVD (optionnelle, chiffrée)": 'NVD API key (optional, encrypted)',
  'Sans clé : 5 requêtes / 30 s. Saisir un espace puis enregistrer pour supprimer la clé.':
    'Without a key: 5 requests / 30 s. Type a space and save to remove the key.',
  Analyse: 'Analysis',
  ["Générer package-lock.json pour les projets JavaScript qui n'en ont pas (clones uniquement, sans "
    + 'exécuter de script)']:
    'Generate package-lock.json for JavaScript projects that lack one (clones only, without running any '
    + 'script)',

  // --- Paramètres : SSO
  'Authentification unique (OIDC)': 'Single sign-on (OIDC)',
  'Activer le SSO': 'Enable SSO',
  'Émetteur (https)': 'Issuer (https)',
  'Identifiant client': 'Client identifier',
  'Secret client (chiffré)': 'Client secret (encrypted)',
  'URL de retour': 'Redirect URL',
  'À déclarer chez le fournisseur : https://<hôte>/api/auth/oidc/callback':
    'To declare with the provider: https://<host>/api/auth/oidc/callback',
  'Rôle par défaut': 'Default role',
  'Revendication des groupes': 'Groups claim',
  'Groupe administrateur': 'Administrator group',
  'Groupe analyste': 'Analyst group',

  // --- Paramètres : journal d'audit et alertes
  'Conservation (jours, 0 = illimitée, 180 minimum)': 'Retention (days, 0 = unlimited, 180 minimum)',
  "Seules les entrées déjà archivées à l'extérieur sont purgées.":
    'Only entries already archived elsewhere are purged.',
  'Collecteur https (SIEM)': 'https collector (SIEM)',
  'Secret de signature HMAC (chiffré)': 'HMAC signing secret (encrypted)',
  'Archivage vers un dossier : variable AUDIT_EXPORT_DIR (ex. partage sauvegardé ou WORM).':
    'Archiving to a folder: the AUDIT_EXPORT_DIR variable (e.g. a backed-up or WORM share).',
  "Alertes vers un canal d'équipe": 'Alerts to a team channel',
  'URL du webhook entrant (https, chiffrée)': 'Incoming webhook URL (https, encrypted)',
  Plateforme: 'Platform',
  'Slack / Mattermost / Rocket.Chat': 'Slack / Mattermost / Rocket.Chat',
  'Microsoft Teams (Workflows)': 'Microsoft Teams (Workflows)',
  Discord: 'Discord',
  'JSON générique (collecteur maison, n8n...)': 'Generic JSON (in-house collector, n8n...)',
  'Gratuit : webhook entrant Slack ou Mattermost, flux "Workflows" Teams, webhook de salon':
    'Free: Slack or Mattermost incoming webhook, Teams "Workflows" flow, Discord channel',
  ['Discord. Seuls le titre et un court résumé sont envoyés (analyses avec constats graves, demandes au '
    + 'catalogue) ;']:
    'webhook. Only the title and a short summary are sent (analyses with serious findings, catalog '
    + 'requests);',
  "le détail reste dans l'application.": 'the detail stays in the application.',
  'Laisser vide pour conserver ; saisir un espace pour supprimer.':
    'Leave empty to keep it; type a space to remove it.',
  'enregistré (laisser vide pour conserver)': 'saved (leave empty to keep it)',
  'non défini': 'not set',

  // --- Paramètres : courriel
  'Notifications par courriel': 'Email notifications',
  'Envoyer aussi les notifications par courriel': 'Also send notifications by email',
  'Serveur SMTP': 'SMTP server',
  Port: 'Port',
  "Adresse d'expédition": 'Sender address',
  'Compte (si le relais en demande un)': 'Account (if the relay asks for one)',
  'Mot de passe (chiffré)': 'Password (encrypted)',
  'Passer la liaison en TLS (STARTTLS)': 'Upgrade the connection to TLS (STARTTLS)',
  'Envoyer un message de test': 'Send a test message',
  'Envoi en cours...': 'Sending...',
  "Enregistrez d'abord les réglages : le test utilise ceux du serveur.":
    'Save the settings first: the test uses the ones held by the server.',
  "Chaque utilisateur reçoit les notifications qui le concernent, à l'adresse de son":
    'Each user receives the notifications that concern them, at the address on their',
  'compte : invitation à un groupe, analyse terminée, demande au catalogue. Sans relais configuré, seules':
    'account: group invitation, finished analysis, catalog request. Without a relay, only',
  "la cloche et le canal d'équipe restent. Avec un compte, le chiffrement de la liaison est obligatoire :":
    'the bell and the team channel remain. With an account, encrypting the connection is mandatory:',
  'le mot de passe ne partira jamais en clair.': 'the password will never be sent in the clear.',

  // --- Paramètres : groupes et informations légales
  Groupes: 'Groups',
  'Tout utilisateur peut créer un groupe (il en devient responsable)':
    'Any user can create a group (and becomes its manager)',
  "L'adhésion est toujours consentie : une invitation doit être acceptée par l'intéressé,":
    'Joining is always consented to: an invitation must be accepted by the person,',
  "une demande d'adhésion par un responsable. Les administrateurs voient et gèrent tous les groupes.":
    'a join request by a manager. Administrators see and manage every group.',
  'Informations légales (RGPD)': 'Legal information (GDPR)',
  'Organisation responsable': 'Organisation responsible',
  'Contact données personnelles (DPO)': 'Data protection contact (DPO)',
  "Charte d'utilisation / mention d'information (affichée à la connexion)":
    'Terms of use / privacy notice (shown on the sign-in page)',
  Enregistrer: 'Save',
  "Paramètres enregistrés (tracés dans le journal d'audit).":
    'Settings saved (recorded in the audit log).',

  // --- Stockage
  'Stockage des analyses': 'Analysis storage',
  'Appliquer la politique de conservation maintenant': 'Apply the retention policy now',
  'Dossiers de travail (clones Git)': 'Work folders (Git clones)',
  'Nettoyer les dossiers de travail maintenant': 'Clean the work folders now',
  'Rien à nettoyer.': 'Nothing to clean.',
  'Chaque analyse clone le dépôt dans un dossier temporaire, supprimé automatiquement à':
    'Each analysis clones the repository into a temporary folder, deleted automatically when it',
  ['la fin (réussite, échec ou arrêt). Il peut en rester après un arrêt brutal de l\'ordinateur ou si un '
    + 'fichier']:
    'ends (success, failure or stop). Some can remain after an abrupt shutdown or if a file',
  ['était verrouillé : ils sont nettoyés au démarrage et toutes les heures. Le bouton ci-dessous le fait '
    + 'tout de']:
    'was locked: they are cleaned at start-up and every hour. The button below does it right',
  'suite, sans toucher aux analyses en cours ni aux rapports.':
    'away, without touching running analyses or reports.',
  'actuellement sur le disque.': 'currently on disk.',
  'Les rapports, CBOM et journaux sont chiffrés au repos (AES-256-GCM).':
    'Reports, CBOMs and logs are encrypted at rest (AES-256-GCM).',
  Local: 'Local',
  Origine: 'Origin',
};
