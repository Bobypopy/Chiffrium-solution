import { api } from '../api.js';
import { formatDate } from '../domain/format.js';
import { PERMISSIONS, session } from '../session.js';
import { badge, copyText, emptyState, h, mount, toast } from '../ui/dom.js';

const TABS = [
  { id: 'overview', label: 'Vue d\'ensemble', permission: PERMISSIONS.MANAGE_SETTINGS },
  { id: 'users', label: 'Utilisateurs', permission: PERMISSIONS.MANAGE_USERS },
  { id: 'audit', label: 'Journal d\'audit', permission: PERMISSIONS.VIEW_AUDIT },
  { id: 'settings', label: 'Paramètres', permission: PERMISSIONS.MANAGE_SETTINGS },
  { id: 'storage', label: 'Stockage', permission: PERMISSIONS.MANAGE_SETTINGS },
];
export const ROLES = Object.freeze([
  { id: 'viewer', label: 'Lecteur', description: 'consulte les rapports' },
  { id: 'analyst', label: 'Analyste', description: 'lance des analyses et supprime les siennes' },
  { id: 'admin', label: 'Administrateur', description: 'tous les droits' },
]);
const AUDIT_PAGE_SIZE = 100;
const BYTES_PER_MB = 1024 * 1024;
/** Valeur renvoyée par l'API à la place d'un secret (SettingsService.MASK). */
const SECRET_MASK = '********';
const ALERT_FORMATS = Object.freeze([
  { id: 'SLACK', label: 'Slack / Mattermost / Rocket.Chat' },
  { id: 'TEAMS', label: 'Microsoft Teams (Workflows)' },
  { id: 'DISCORD', label: 'Discord' },
  { id: 'GENERIC', label: 'JSON générique (collecteur maison, n8n...)' },
]);

/** Administration : onglets filtrés selon les permissions de l'utilisateur. */
export function renderAdmin(container, { tab }) {
  const available = TABS.filter((t) => session.can(t.permission));
  if (!available.length) {
    mount(container, h('section', { class: 'card' }, emptyState('Accès réservé aux administrateurs.')));
    return;
  }
  const active = available.find((t) => t.id === tab) ?? available[0];
  const body = h('div', { class: 'tab-body' });
  mount(container,
    h('div', { class: 'tabs', role: 'tablist' }, available.map((t) => h('button', {
      role: 'tab', type: 'button', 'aria-selected': String(t.id === active.id),
      onclick: () => { location.hash = `#/admin/${t.id}`; },
    }, t.label))),
    body);
  const views = { overview: overviewTab, users: usersTab, audit: auditTab, settings: settingsTab, storage: storageTab };
  views[active.id](body);
}

// ---------------------------------------------------------------- Vue d'ensemble

/** Ce qui demande l'attention d'un administrateur, avec un lien vers l'écran concerné. */
async function overviewTab(container) {
  mount(container, h('p', { class: 'muted' }, 'Chargement...'));
  try {
    const o = await api.adminOverview();
    const tile = (value, label, href, tone = '') => h(href ? 'a' : 'div',
      { class: `stat-tile ${tone ? `tone-${tone}` : ''}`.trim(), href },
      h('div', { class: 'stat-value' }, String(value)), h('div', { class: 'stat-label' }, label));
    const attention = o.pendingCatalogRequests + o.pendingJoinRequests + o.analysesFailedRecently
      + (o.auditIntact ? 0 : 1);
    mount(container,
      h('section', { class: 'card' },
        h('div', { class: 'card-header' }, h('h2', {}, 'À traiter'),
          attention ? badge({ label: `${attention} point(s) d'attention`, icon: '!', tone: 'serious' })
            : badge({ label: 'Rien à signaler', icon: '✓', tone: 'good' })),
        h('div', { class: 'overview-grid' },
          tile(o.pendingCatalogRequests, 'demande(s) au catalogue en attente', '#/catalog',
            o.pendingCatalogRequests ? 'serious' : 'good'),
          tile(o.pendingJoinRequests, 'demande(s) d\'adhésion à un groupe', '#/groups',
            o.pendingJoinRequests ? 'warning' : 'good'),
          tile(o.analysesFailedRecently, 'analyse(s) en échec (24 h)', '#/analyses',
            o.analysesFailedRecently ? 'serious' : 'good'),
          tile(o.failedLoginsRecently, 'échec(s) de connexion (24 h)', '#/admin/audit',
            o.failedLoginsRecently > 10 ? 'critical' : o.failedLoginsRecently ? 'warning' : 'good'),
          tile(o.auditIntact ? 'Intègre' : 'Altéré', 'journal d\'audit', '#/admin/audit',
            o.auditIntact ? 'good' : 'critical'))),
      h('section', { class: 'card' }, h('h2', {}, 'Activité'),
        h('div', { class: 'overview-grid' },
          tile(o.users, 'compte(s)', '#/admin/users'),
          tile(o.groups, 'groupe(s)', '#/groups'),
          tile(o.analyses, 'analyse(s) conservée(s)', '#/analyses'),
          tile(`${o.analysesRunning} / ${o.analysesQueued}`, 'en cours / en attente', '#/analyses'),
          tile(`${(o.usedBytes / BYTES_PER_MB).toFixed(1)} Mo`, 'stockage utilisé', '#/admin/storage'))),
      h('p', { class: 'hint' }, 'Les notifications (cloche en haut de page) vous préviennent aussi en temps réel ; un ',
        'canal d\'équipe gratuit (Slack, Teams, Discord, Mattermost) peut les relayer : voir Paramètres > Alertes.'));
  } catch (error) {
    mount(container, emptyState(error.message));
  }
}

// ---------------------------------------------------------------- Utilisateurs

async function usersTab(container) {
  const list = h('div', { class: 'table-wrap' }, h('p', { class: 'muted' }, 'Chargement...'));
  const secretBox = h('div', { class: 'card secret-box', hidden: true, role: 'status' });

  const showTemporary = ({ user, temporaryPassword }) => {
    secretBox.hidden = false;
    const value = h('code', { class: 'secret-value' }, temporaryPassword);
    mount(secretBox,
      h('h3', {}, `Mot de passe provisoire de "${user.username}"`),
      h('p', {}, 'Transmettez-le par un canal sûr : il ne sera plus affiché. L\'utilisateur devra le changer à sa ',
        'première connexion.'),
      h('div', { class: 'actions' }, value,
        h('button', { class: 'button small', type: 'button',
          onclick: () => copyText(temporaryPassword) },
        'Copier'),
        h('button', { class: 'button small ghost', type: 'button', onclick: () => { secretBox.hidden = true; } },
          'Masquer')));
  };

  const refresh = async () => {
    try {
      const users = await api.listUsers();
      mount(list, usersTable(users, refresh, showTemporary));
    } catch (error) {
      mount(list, emptyState(error.message));
    }
  };

  mount(container,
    h('section', { class: 'card' }, h('h2', {}, 'Nouvel utilisateur'), createUserForm(async (user) => {
      showTemporary(await api.createUser(user));
      refresh();
    }), h('p', { class: 'hint' }, ROLES.map((r) => `${r.label} : ${r.description}`).join(' - '))),
    secretBox,
    h('section', { class: 'card' }, h('h2', {}, 'Comptes'), list));
  refresh();
}

function createUserForm(onCreate) {
  const username = h('input', { id: 'new-user', required: true, autocomplete: 'off', pattern: '[A-Za-z0-9][A-Za-z0-9._@\\-]{2,63}' });
  const displayName = h('input', { id: 'new-name' });
  const email = h('input', { id: 'new-email', type: 'email' });
  const role = h('select', { id: 'new-role' }, ROLES.map((r) => h('option', { value: r.id, selected: r.id === 'viewer' },
    r.label)));
  return h('form', {
    class: 'form-grid',
    onsubmit: async (event) => {
      event.preventDefault();
      try {
        await onCreate({ username: username.value.trim(), displayName: displayName.value.trim() || null,
          email: email.value.trim() || null, role: role.value });
        event.target.reset();
        toast('Compte créé.', 'good');
      } catch (error) {
        toast(error.message, 'critical');
      }
    },
  },
  h('div', { class: 'field' }, h('label', { for: 'new-user' }, 'Identifiant'), username),
  h('div', { class: 'field' }, h('label', { for: 'new-name' }, 'Nom affiché'), displayName),
  h('div', { class: 'field' }, h('label', { for: 'new-email' }, 'E-mail'), email),
  h('div', { class: 'field' }, h('label', { for: 'new-role' }, 'Rôle'), role),
  h('div', { class: 'actions' }, h('button', { class: 'button primary', type: 'submit' }, 'Créer')));
}

function usersTable(users, refresh, showTemporary) {
  const me = session.current()?.user?.id;
  const act = (action) => async () => {
    try {
      await action();
      refresh();
    } catch (error) {
      toast(error.message, 'critical');
    }
  };
  return h('table', { class: 'table' },
    h('thead', {}, h('tr', {}, ['Compte', 'Rôle', 'Origine', 'État', 'Dernière connexion', '']
      .map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, users.map((user) => h('tr', {},
      h('td', {}, h('strong', {}, user.displayName), h('div', { class: 'muted small' },
        user.username, user.email ? ` - ${user.email}` : '')),
      h('td', {}, h('select', {
        'aria-label': `Rôle de ${user.username}`,
        onchange: (e) => act(() => api.updateUser(user.id, { role: e.target.value }))(),
      }, ROLES.map((r) => h('option', { value: r.id, selected: r.id === user.role }, r.label)))),
      h('td', {}, user.source === 'oidc' ? 'SSO' : 'Local'),
      h('td', {}, badge(user.enabled
        ? (user.lockedUntil && new Date(user.lockedUntil) > new Date()
          ? { label: 'Verrouillé', icon: '!', tone: 'serious' } : { label: 'Actif', icon: '✓', tone: 'good' })
        : { label: 'Désactivé', icon: '✕', tone: 'muted' }),
      user.mustChangePassword ? h('div', { class: 'muted small' }, 'mot de passe provisoire') : null),
      h('td', { class: 'small' }, formatDate(user.lastLoginAt)),
      h('td', { class: 'actions' },
        user.id === me ? h('span', { class: 'muted small' }, 'vous') : h('button', {
          class: 'button small ghost', type: 'button',
          onclick: act(() => api.updateUser(user.id, { enabled: !user.enabled })),
        }, user.enabled ? 'Désactiver' : 'Réactiver'),
        user.source === 'local' ? h('button', {
          class: 'button small ghost', type: 'button',
          onclick: async () => {
            if (!window.confirm(`Réinitialiser le mot de passe de ${user.username} ? Ses sessions seront fermées.`)) return;
            try {
              showTemporary(await api.resetPassword(user.id));
              refresh();
            } catch (error) {
              toast(error.message, 'critical');
            }
          },
        }, 'Réinitialiser le mot de passe') : null)))));
}

// ---------------------------------------------------------------- Audit

/**
 * État de l'archivage externe. Un collecteur injoignable n'apparaissait que dans les journaux du serveur :
 * l'administrateur pouvait croire son journal archivé alors qu'il ne l'était plus depuis des jours.
 */
function exportState(state) {
  const valeur = (v) => (v && v !== 'null' ? v : null);
  if (!state || !valeur(state.targets)) {
    return h('div', { class: 'muted small' }, 'Archivage externe non configuré : le journal reste uniquement '
      + 'dans la base (voir Paramètres > Journal d\'audit).');
  }
  const succes = valeur(state.lastSuccessAt);
  const erreur = valeur(state.error);
  return h('div', { class: 'archive-state' },
    badge(erreur
      ? { label: 'Archivage en échec', icon: '✕', tone: 'critical' }
      : { label: 'Archivage à jour', icon: '✓', tone: 'good' }),
    h('span', { class: 'muted small' }, ` vers ${state.targets}`,
      succes ? ` - dernier envoi réussi le ${formatDate(succes)}` : ' - aucun envoi réussi pour l\'instant',
      erreur ? ` - dernière erreur : ${erreur}` : ''));
}

async function auditTab(container) {
  const filters = { actor: '', action: '' };
  const rows = h('tbody');
  const integrity = h('div', { class: 'integrity' });
  const more = h('button', { class: 'button ghost', type: 'button', hidden: true }, 'Afficher plus');
  let offset = 0;

  const load = async (append) => {
    try {
      const events = await api.searchAudit({ ...filters, limit: AUDIT_PAGE_SIZE, offset });
      const lines = events.map((e) => h('tr', {},
        h('td', { class: 'mono small' }, String(e.sequence)),
        h('td', { class: 'small' }, formatDate(e.timestamp)),
        h('td', {}, e.actor),
        h('td', {}, h('code', {}, e.action)),
        h('td', { class: 'small' }, e.target ?? ''),
        h('td', { class: 'small' }, e.details ?? ''),
        h('td', { class: 'small mono' }, e.sourceIp ?? '')));
      if (append) rows.append(...lines);
      else mount(rows, lines.length ? lines : h('tr', {}, h('td', { colspan: 7 }, emptyState('Aucun événement.'))));
      more.hidden = events.length < AUDIT_PAGE_SIZE;
    } catch (error) {
      mount(rows, h('tr', {}, h('td', { colspan: 7 }, emptyState(error.message))));
    }
  };

  const verify = async () => {
    mount(integrity, h('span', { class: 'muted' }, 'Vérification...'));
    try {
      const result = await api.verifyAudit();
      mount(integrity, result.intact
        ? badge({ label: `Chaîne intègre (${result.entries} entrées)`, icon: '✓', tone: 'good' })
        : badge({ label: `Altération détectée à l'entrée no ${result.firstBrokenSeq} : ${result.problem}`, icon: '✕',
          tone: 'critical' }),
      h('span', { class: 'muted small' }, result.anchoredUpTo
        ? ` - archivé à l'extérieur jusqu'à l'entrée no ${result.anchoredUpTo}`
        : ' - aucun archivage externe (configurer un dossier ou un collecteur)',
      result.purgedUpTo ? ` - entrées purgées jusqu'au no ${result.purgedUpTo}` : ''),
      exportState(result.export));
    } catch (error) {
      mount(integrity, h('span', { class: 'error-text' }, error.message));
    }
  };

  more.addEventListener('click', () => {
    offset += AUDIT_PAGE_SIZE;
    load(true);
  });
  const search = (key, placeholder) => h('input', {
    type: 'search', placeholder, 'aria-label': placeholder,
    onchange: (e) => { filters[key] = e.target.value.trim(); offset = 0; load(false); },
  });

  mount(container,
    h('section', { class: 'card' },
      h('div', { class: 'card-header' }, h('h2', {}, 'Journal d\'audit'),
        h('div', { class: 'actions' },
          h('button', { class: 'button ghost', type: 'button', onclick: verify }, 'Vérifier l\'intégrité'),
          h('button', { class: 'button ghost', type: 'button',
            onclick: () => api.exportAudit().catch((e) => toast(e.message, 'critical')) }, 'Exporter'))),
      h('p', { class: 'hint' }, 'Journal en ajout seul : chaque entrée contient l\'empreinte SHA-256 de la précédente, ',
        'toute modification ou suppression a posteriori est détectée. Les secrets n\'y figurent jamais.'),
      integrity,
      h('div', { class: 'filters' }, search('actor', 'Utilisateur'), search('action', 'Action (ex. LOGIN_FAILURE)'))),
    h('section', { class: 'card table-wrap' }, h('table', { class: 'table' },
      h('thead', {}, h('tr', {}, ['No', 'Date', 'Utilisateur', 'Action', 'Objet', 'Détail', 'Adresse']
        .map((t) => h('th', { scope: 'col' }, t)))), rows), more));
  load(false);
  verify();
}

// ---------------------------------------------------------------- Paramètres

/**
 * Envoi d'un message de test à l'adresse de l'administrateur connecté.
 *
 * Un relais SMTP se configure rarement du premier coup (port, TLS, compte) : sans essai, l'erreur ne se
 * découvrirait qu'à la première vraie notification, et seulement dans les journaux du serveur.
 */
function testEmailButton() {
  const status = h('span', { class: 'muted small' });
  const button = h('button', { class: 'button small', type: 'button', onclick: async () => {
    button.disabled = true;
    status.textContent = 'Envoi en cours...';
    try {
      const result = await api.testEmail();
      status.textContent = `Message envoyé à ${result.sentTo}. Vérifiez la boîte (et les indésirables).`;
    } catch (error) {
      status.textContent = `Échec : ${error.message}`;
    } finally {
      button.disabled = false;
    }
  } }, 'Envoyer un message de test');
  return h('div', { class: 'live-status' }, button, status,
    h('span', { class: 'muted small' }, 'Enregistrez d\'abord les réglages : le test utilise ceux du serveur.'));
}

async function settingsTab(container) {
  mount(container, h('p', { class: 'muted' }, 'Chargement...'));
  let settings;
  try {
    settings = await api.getSettings();
  } catch (error) {
    mount(container, emptyState(error.message));
    return;
  }
  const inputs = {};
  const number = (path, value, min, max) => (inputs[path] = h('input', { id: path, type: 'number', min, max, value }));
  const check = (path, value) => (inputs[path] = h('input', { id: path, type: 'checkbox', checked: Boolean(value) }));
  const text = (path, value, type = 'text') => (inputs[path] = h('input', { id: path, type, value: value ?? '' }));
  const secret = (path, value) => (inputs[path] = h('input', {
    id: path, type: 'password', autocomplete: 'new-password',
    placeholder: value === SECRET_MASK ? 'enregistré (laisser vide pour conserver)' : 'non défini',
  }));
  const row = (path, labelText, input, hint) => h('div', { class: 'field' },
    h('label', { for: path }, labelText), input, hint ? h('span', { class: 'muted small' }, hint) : null);
  const checkRow = (input, labelText) => h('label', { class: 'inline-check' }, input, ` ${labelText}`);
  const { storage, sessions, intelligence, analysis, oidc, audit, organization, collaboration, alerts,
    email } = settings;
  const alertFormat = inputs['alerts.format'] = h('select', { id: 'alerts.format' },
    ALERT_FORMATS.map((f) => h('option', { value: f.id, selected: f.id === (alerts?.format ?? 'GENERIC') }, f.label)));
  const role = inputs['oidc.defaultRole'] = h('select', { id: 'oidc.defaultRole' },
    ROLES.filter((r) => r.id !== 'admin').map((r) => h('option', { value: r.id, selected: r.id === oidc.defaultRole },
      r.label)));

  const form = h('form', {
    onsubmit: async (event) => {
      event.preventDefault();
      const value = (path) => inputs[path].value.trim();
      const int = (path) => Number(inputs[path].value);
      // Champ vide : secret conservé ; un simple espace est transmis tel quel et supprime le secret.
      const kept = (path) => (inputs[path].value === '' ? SECRET_MASK : inputs[path].value);
      try {
        settings = await api.saveSettings({
          storage: { retentionDays: int('storage.retentionDays'), maxStorageMb: int('storage.maxStorageMb'),
            keepRawOutputs: inputs['storage.keepRawOutputs'].checked },
          sessions: { idleMinutes: int('sessions.idleMinutes'), maxHours: int('sessions.maxHours') },
          intelligence: { osv: inputs['intelligence.osv'].checked, kev: inputs['intelligence.kev'].checked,
            epss: inputs['intelligence.epss'].checked, nvd: inputs['intelligence.nvd'].checked,
            nvdApiKey: kept('intelligence.nvdApiKey') },
          analysis: { generateNpmLockfile: inputs['analysis.generateNpmLockfile'].checked },
          audit: { retentionDays: int('audit.retentionDays'), webhookUrl: value('audit.webhookUrl') || null,
            webhookSecret: kept('audit.webhookSecret') },
          collaboration: { usersCanCreateGroups: inputs['collaboration.usersCanCreateGroups'].checked },
          alerts: { webhookUrl: kept('alerts.webhookUrl'), format: alertFormat.value },
          email: { enabled: inputs['email.enabled'].checked, host: value('email.host') || null,
            port: int('email.port'), startTls: inputs['email.startTls'].checked,
            username: value('email.username') || null, password: kept('email.password'),
            from: value('email.from') || null },
          organization: { name: value('organization.name') || null,
            privacyContact: value('organization.privacyContact') || null,
            usageNotice: inputs['organization.usageNotice'].value.trim() || null },
          oidc: { enabled: inputs['oidc.enabled'].checked, issuer: value('oidc.issuer') || null,
            clientId: value('oidc.clientId') || null, clientSecret: kept('oidc.clientSecret'),
            redirectUri: value('oidc.redirectUri') || null, defaultRole: role.value,
            groupsClaim: value('oidc.groupsClaim') || null, adminGroup: value('oidc.adminGroup') || null,
            analystGroup: value('oidc.analystGroup') || null },
        });
        toast('Paramètres enregistrés (tracés dans le journal d\'audit).', 'good');
        settingsTab(container);
      } catch (error) {
        toast(error.message, 'critical');
      }
    },
  },
  h('section', { class: 'card' }, h('h2', {}, 'Conservation des données'),
    h('div', { class: 'form-grid' },
      row('storage.retentionDays', 'Rétention (jours, 0 = illimitée)', number('storage.retentionDays', storage.retentionDays, 0, 3650)),
      row('storage.maxStorageMb', 'Volume maximal (Mo, 0 = illimité)', number('storage.maxStorageMb', storage.maxStorageMb, 0, 1048576),
        'Au-delà, les analyses les plus anciennes sont purgées.')),
    checkRow(check('storage.keepRawOutputs', storage.keepRawOutputs),
      'Conserver les sorties brutes de cdxgen (chiffrées ; volumineuses)')),
  h('section', { class: 'card' }, h('h2', {}, 'Sessions'),
    h('div', { class: 'form-grid' },
      row('sessions.idleMinutes', 'Expiration après inactivité (min)', number('sessions.idleMinutes', sessions.idleMinutes, 5, 480)),
      row('sessions.maxHours', 'Durée maximale (h)', number('sessions.maxHours', sessions.maxHours, 1, 168)))),
  h('section', { class: 'card' }, h('h2', {}, 'Sources de vulnérabilités'),
    h('div', { class: 'checks' },
      checkRow(check('intelligence.osv', intelligence.osv), 'OSV (dépendances, sans clé)'),
      checkRow(check('intelligence.kev', intelligence.kev), 'CISA KEV (vulnérabilités exploitées)'),
      checkRow(check('intelligence.epss', intelligence.epss), 'EPSS (probabilité d\'exploitation)'),
      checkRow(check('intelligence.nvd', intelligence.nvd), 'NVD (score CVSS officiel)')),
    row('intelligence.nvdApiKey', 'Clé d\'API NVD (optionnelle, chiffrée)', secret('intelligence.nvdApiKey', intelligence.nvdApiKey),
      'Sans clé : 5 requêtes / 30 s. Saisir un espace puis enregistrer pour supprimer la clé.')),
  h('section', { class: 'card' }, h('h2', {}, 'Analyse'),
    checkRow(check('analysis.generateNpmLockfile', analysis.generateNpmLockfile),
      'Générer package-lock.json pour les projets JavaScript qui n\'en ont pas (clones uniquement, sans exécuter de script)')),
  h('section', { class: 'card' }, h('h2', {}, 'Authentification unique (OIDC)'),
    checkRow(check('oidc.enabled', oidc.enabled), 'Activer le SSO'),
    h('div', { class: 'form-grid' },
      row('oidc.issuer', 'Émetteur (https)', text('oidc.issuer', oidc.issuer, 'url')),
      row('oidc.clientId', 'Identifiant client', text('oidc.clientId', oidc.clientId)),
      row('oidc.clientSecret', 'Secret client (chiffré)', secret('oidc.clientSecret', oidc.clientSecret)),
      row('oidc.redirectUri', 'URL de retour', text('oidc.redirectUri', oidc.redirectUri, 'url'),
        'À déclarer chez le fournisseur : https://<hôte>/api/auth/oidc/callback'),
      row('oidc.defaultRole', 'Rôle par défaut', role),
      row('oidc.groupsClaim', 'Revendication des groupes', text('oidc.groupsClaim', oidc.groupsClaim)),
      row('oidc.adminGroup', 'Groupe administrateur', text('oidc.adminGroup', oidc.adminGroup)),
      row('oidc.analystGroup', 'Groupe analyste', text('oidc.analystGroup', oidc.analystGroup)))),
  h('section', { class: 'card' }, h('h2', {}, 'Journal d\'audit'),
    h('div', { class: 'form-grid' },
      row('audit.retentionDays', 'Conservation (jours, 0 = illimitée, 180 minimum)',
        number('audit.retentionDays', audit.retentionDays, 0, 3650),
        'Seules les entrées déjà archivées à l\'extérieur sont purgées.'),
      row('audit.webhookUrl', 'Collecteur https (SIEM)', text('audit.webhookUrl', audit.webhookUrl, 'url')),
      row('audit.webhookSecret', 'Secret de signature HMAC (chiffré)', secret('audit.webhookSecret', audit.webhookSecret))),
    h('p', { class: 'hint' }, 'Archivage vers un dossier : variable AUDIT_EXPORT_DIR (ex. partage sauvegardé ou WORM).')),
  h('section', { class: 'card' }, h('h2', {}, 'Groupes'),
    checkRow(check('collaboration.usersCanCreateGroups', collaboration?.usersCanCreateGroups ?? true),
      'Tout utilisateur peut créer un groupe (il en devient responsable)'),
    h('p', { class: 'hint' }, 'L\'adhésion est toujours consentie : une invitation doit être acceptée par l\'intéressé, ',
      'une demande d\'adhésion par un responsable. Les administrateurs voient et gèrent tous les groupes.')),
  h('section', { class: 'card' }, h('h2', {}, 'Alertes vers un canal d\'équipe'),
    h('div', { class: 'form-grid' },
      row('alerts.webhookUrl', 'URL du webhook entrant (https, chiffrée)', secret('alerts.webhookUrl', alerts?.webhookUrl),
        'Laisser vide pour conserver ; saisir un espace pour supprimer.'),
      row('alerts.format', 'Plateforme', alertFormat)),
    h('p', { class: 'hint' }, 'Gratuit : webhook entrant Slack ou Mattermost, flux "Workflows" Teams, webhook de salon ',
      'Discord. Seuls le titre et un court résumé sont envoyés (analyses avec constats graves, demandes au catalogue) ; ',
      'le détail reste dans l\'application.')),
  h('section', { class: 'card' }, h('h2', {}, 'Notifications par courriel'),
    checkRow(check('email.enabled', email?.enabled), 'Envoyer aussi les notifications par courriel'),
    h('div', { class: 'form-grid' },
      row('email.host', 'Serveur SMTP', text('email.host', email?.host)),
      row('email.port', 'Port', number('email.port', email?.port ?? 587, 1, 65535),
        '587 (STARTTLS), 465 (chiffré d\'emblée) ou 25 (relais interne).'),
      row('email.from', 'Adresse d\'expédition', text('email.from', email?.from, 'email')),
      row('email.username', 'Compte (si le relais en demande un)', text('email.username', email?.username)),
      row('email.password', 'Mot de passe (chiffré)', secret('email.password', email?.password),
        'Laisser vide pour conserver ; saisir un espace pour supprimer.')),
    checkRow(check('email.startTls', email?.startTls ?? true), 'Passer la liaison en TLS (STARTTLS)'),
    testEmailButton(),
    h('p', { class: 'hint' }, 'Chaque utilisateur reçoit les notifications qui le concernent, à l\'adresse de son ',
      'compte : invitation à un groupe, analyse terminée, demande au catalogue. Sans relais configuré, seules ',
      'la cloche et le canal d\'équipe restent. Avec un compte, le chiffrement de la liaison est obligatoire : ',
      'le mot de passe ne partira jamais en clair.')),
  h('section', { class: 'card' }, h('h2', {}, 'Informations légales (RGPD)'),
    h('div', { class: 'form-grid' },
      row('organization.name', 'Organisation responsable', text('organization.name', organization.name)),
      row('organization.privacyContact', 'Contact données personnelles (DPO)',
        text('organization.privacyContact', organization.privacyContact))),
    row('organization.usageNotice', 'Charte d\'utilisation / mention d\'information (affichée à la connexion)',
      (inputs['organization.usageNotice'] = h('textarea', { id: 'organization.usageNotice', rows: 6, maxlength: 10000 },
        organization.usageNotice ?? '')))),
  h('div', { class: 'actions' }, h('button', { class: 'button primary', type: 'submit' }, 'Enregistrer')));
  mount(container, form);
}

// ---------------------------------------------------------------- Stockage

async function storageTab(container) {
  mount(container, h('p', { class: 'muted' }, 'Chargement...'));
  try {
    const storage = await api.getStorage();
    const usedMb = storage.usedBytes / BYTES_PER_MB;
    const workspaceMb = (storage.workspaceBytes ?? 0) / BYTES_PER_MB;
    const share = storage.maxStorageMb ? Math.min(1, usedMb / storage.maxStorageMb) : 0;
    mount(container, h('section', { class: 'card' },
      h('h2', {}, 'Dossiers de travail (clones Git)'),
      h('p', {}, h('strong', {}, `${workspaceMb.toFixed(1)} Mo`), ' actuellement sur le disque.'),
      h('p', { class: 'hint' }, 'Chaque analyse clone le dépôt dans un dossier temporaire, supprimé automatiquement à ',
        'la fin (réussite, échec ou arrêt). Il peut en rester après un arrêt brutal de l\'ordinateur ou si un fichier ',
        'était verrouillé : ils sont nettoyés au démarrage et toutes les heures. Le bouton ci-dessous le fait tout de ',
        'suite, sans toucher aux analyses en cours ni aux rapports.'),
      h('button', {
        class: 'button', type: 'button',
        onclick: async () => {
          try {
            const result = await api.cleanWorkspaces();
            toast(result.removed ? `${result.removed} dossier(s) supprimé(s), `
              + `${(result.bytesFreed / BYTES_PER_MB).toFixed(1)} Mo libéré(s).` : 'Rien à nettoyer.', 'good');
            storageTab(container);
          } catch (error) {
            toast(error.message, 'critical');
          }
        },
      }, 'Nettoyer les dossiers de travail maintenant')),
    h('section', { class: 'card' },
      h('h2', {}, 'Stockage des analyses'),
      h('p', {}, h('strong', {}, `${usedMb.toFixed(1)} Mo`), storage.maxStorageMb
        ? ` utilisés sur ${storage.maxStorageMb} Mo` : ' utilisés (pas de quota)'),
      storage.maxStorageMb ? h('div', { class: `meter tone-${share > 0.9 ? 'critical' : share > 0.7 ? 'serious' : 'good'}` },
        h('div', { class: 'meter-fill', style: { width: `${share * 100}%` } })) : null,
      h('p', { class: 'hint' }, storage.retentionDays
        ? `Les analyses de plus de ${storage.retentionDays} jours sont supprimées automatiquement (vérification horaire).`
        : 'Rétention illimitée.', ' Les rapports, CBOM et journaux sont chiffrés au repos (AES-256-GCM).'),
      h('button', {
        class: 'button', type: 'button',
        onclick: async () => {
          try {
            const result = await api.purgeStorage();
            toast(`${result.purgedByAge + result.purgedByQuota} analyse(s) purgée(s), `
              + `${result.workspacesCleaned ?? 0} dossier(s) de travail supprimé(s).`, 'good');
            storageTab(container);
          } catch (error) {
            toast(error.message, 'critical');
          }
        },
      }, 'Appliquer la politique de conservation maintenant')));
  } catch (error) {
    mount(container, emptyState(error.message));
  }
}
