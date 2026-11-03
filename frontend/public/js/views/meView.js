import { api } from '../api.js';
import { formatDate } from '../domain/format.js';
import { session } from '../session.js';
import { emptyState, h, mount, toast } from '../ui/dom.js';
import { notificationList } from '../ui/notifications.js';

const ROLE_LABELS = { viewer: 'Lecteur', analyst: 'Analyste', admin: 'Administrateur' };
const REQUEST_KINDS = { create: 'Ajout', update: 'Modification', delete: 'Suppression' };
const REQUEST_STATUS = { pending: 'en attente', approved: 'acceptée', rejected: 'refusée', withdrawn: 'retirée' };

/**
 * Mon espace : profil, invitations et groupes, demandes au catalogue, notifications, export de mes données (RGPD).
 */
export async function renderMe(container) {
  const user = session.current()?.user;
  const invitations = h('div', {}, h('p', { class: 'muted' }, 'Chargement...'));
  const groups = h('div');
  const requests = h('div');
  const notifications = h('div');

  const run = (action, success) => async () => {
    try {
      await action();
      if (success) toast(success, 'good');
      refresh();
    } catch (error) {
      toast(error.message, 'critical');
    }
  };

  async function refresh() {
    const [pending, memberships, catalogRequests, list] = await Promise.all([
      api.myInvitations(), api.myGroups(), api.listCatalogRequests().catch(() => []),
      api.listNotifications()]).catch((error) => {
      mount(invitations, emptyState(error.message));
      return [];
    });
    if (!pending) return;
    mount(invitations, pending.received.length ? h('ul', { class: 'invite-list' }, pending.received.map((i) => h('li', {},
      h('div', {}, h('strong', {}, i.groupName), h('span', { class: 'muted small' },
        ` - invité par ${i.createdBy}${i.manager ? ', comme responsable' : ''}`),
      i.message ? h('p', { class: 'small prewrap quote' }, i.message) : null),
      h('div', { class: 'actions' },
        h('button', { class: 'button primary small', type: 'button',
          onclick: run(() => api.acceptInvitation(i.id), `Vous avez rejoint "${i.groupName}".`) }, 'Accepter'),
        h('button', { class: 'button ghost small', type: 'button',
          onclick: run(() => api.declineInvitation(i.id), 'Invitation déclinée.') }, 'Refuser')))))
      : emptyState('Aucune invitation en attente.'),
    pending.sent.length ? h('p', { class: 'muted small' }, 'Demandes d\'adhésion envoyées : ',
      pending.sent.map((s) => s.groupName).join(', ')) : null);
    mount(groups, memberships.length ? h('ul', { class: 'invite-list' }, memberships.map((m) => h('li', {},
      h('div', {}, h('strong', {}, m.groupName), m.manager ? h('span', { class: 'tag' }, 'responsable') : null),
      h('button', { class: 'button ghost small', type: 'button', onclick: run(async () => {
        if (window.confirm(`Quitter le groupe "${m.groupName}" ?`)) await api.leaveGroup(m.groupId);
      }) }, 'Quitter'))))
      : emptyState('Aucun groupe.'),
    h('p', { class: 'hint' }, h('a', { href: '#/groups' }, 'Voir l\'annuaire des groupes'), ' pour en rejoindre un.'));
    const mine = catalogRequests.filter((r) => r.requestedBy === user?.username);
    mount(requests, mine.length ? h('table', { class: 'table' },
      h('thead', {}, h('tr', {}, ['Demande', 'Statut', 'Date', 'Réponse'].map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', {}, mine.map((r) => h('tr', {},
        h('td', {}, `${REQUEST_KINDS[r.kind] ?? r.kind} - ${r.algorithmId ?? r.proposal?.id ?? ''}`),
        h('td', {}, REQUEST_STATUS[r.status] ?? r.status),
        h('td', { class: 'small' }, formatDate(r.createdAt)),
        h('td', { class: 'small' }, r.reviewComment ?? '')))))
      : emptyState('Aucune demande au catalogue.'));
    mount(notifications, notificationList(list, { onChange: refresh }));
  }

  mount(container,
    h('div', { class: 'grid-2' },
      profileCard(user),
      h('section', { class: 'card' }, h('h2', {}, 'Invitations'), invitations)),
    h('div', { class: 'grid-2' },
      h('section', { class: 'card' }, h('h2', {}, 'Mes groupes'), groups),
      h('section', { class: 'card' }, h('h2', {}, 'Mes demandes au catalogue'), requests)),
    h('section', { class: 'card' },
      h('div', { class: 'card-header' }, h('h2', {}, 'Notifications'),
        h('button', { class: 'button ghost small', type: 'button',
          onclick: run(() => api.markNotificationsRead(null), 'Tout est marqué comme lu.') }, 'Tout marquer comme lu')),
      notifications),
    h('section', { class: 'card' }, h('h2', {}, 'Mes données'),
      h('p', {}, 'Téléchargez les données personnelles que Chiffrium conserve sur vous : compte, groupes, favoris, ',
        'analyses demandées, demandes au catalogue, notifications et votre historique dans le journal d\'audit.'),
      h('button', { class: 'button', type: 'button',
        onclick: () => api.exportMyData().catch((e) => toast(e.message, 'critical')) }, 'Exporter mes données (JSON)'),
      h('p', { class: 'hint' }, 'Pour une rectification ou une suppression de compte, contactez un administrateur ',
        '(voir la page À propos).')));
  refresh();
}

function profileCard(user) {
  if (!user) return null;
  const displayName = h('input', { id: 'me-name', value: user.displayName ?? '', maxlength: 100 });
  const email = h('input', { id: 'me-email', type: 'email', value: user.email ?? '', maxlength: 200 });
  const sso = user.source === 'oidc';
  return h('section', { class: 'card' }, h('h2', {}, 'Profil'),
    h('dl', { class: 'facts' },
      h('dt', {}, 'Identifiant'), h('dd', {}, user.username),
      h('dt', {}, 'Rôle'), h('dd', {}, ROLE_LABELS[user.role] ?? user.role),
      h('dt', {}, 'Connexion'), h('dd', {}, sso ? 'Authentification unique (SSO)' : 'Compte local'),
      h('dt', {}, 'Dernière connexion'), h('dd', {}, formatDate(user.lastLoginAt))),
    h('form', {
      class: 'form-grid',
      onsubmit: async (event) => {
        event.preventDefault();
        try {
          const updated = await api.updateProfile({ displayName: displayName.value.trim() || null,
            email: email.value.trim() });
          session.update({ ...session.current(), user: { ...session.current().user, ...updated } });
          toast('Profil mis à jour.', 'good');
        } catch (error) {
          toast(error.message, 'critical');
        }
      },
    },
    h('div', { class: 'field' }, h('label', { for: 'me-name' }, 'Nom affiché'), displayName),
    h('div', { class: 'field' }, h('label', { for: 'me-email' }, 'E-mail'), email),
    h('div', { class: 'actions' }, h('button', { class: 'button primary', type: 'submit' }, 'Enregistrer'))),
    sso ? null : h('p', {}, h('a', { class: 'button ghost', href: '#/password' }, 'Changer mon mot de passe')),
    sso ? h('p', { class: 'hint' }, 'Nom et e-mail peuvent être remplacés à la prochaine connexion SSO.') : null);
}
