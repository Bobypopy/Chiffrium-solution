import { api } from '../api.js';
import { formatDate, plural, shortTarget } from '../domain/format.js';
import { groupSummary } from '../domain/jobs.js';
import { scoreTone } from '../domain/report.js';
import { statTile } from '../ui/charts.js';
import { PERMISSIONS, session } from '../session.js';
import { badge, emptyState, h, mount, toast } from '../ui/dom.js';

const VISIBILITIES = Object.freeze([
  { id: 'private', label: 'Privé', description: 'visible de ses seuls membres, on y entre sur invitation' },
  { id: 'public', label: 'Public', description: 'visible dans l\'annuaire, chacun peut demander à le rejoindre' },
]);
const ROLE_BADGES = {
  manager: { label: 'Responsable', icon: '★', tone: 'good' },
  member: { label: 'Membre', icon: '✓', tone: 'neutral' },
  admin: { label: 'Administration', icon: '⚙', tone: 'muted' },
};

/**
 * Groupes : mes groupes, annuaire des groupes publics, invitations reçues. L'adhésion est toujours consentie :
 * l'invité accepte ou refuse, un responsable accepte ou refuse les demandes, chacun peut quitter un groupe.
 */
export async function renderGroups(container) {
  // Analyses visibles de l'utilisateur : servent à la synthèse de chaque groupe, sans appel dédié.
  let analysesByGroup = [];
  const invitations = h('div');
  const mine = h('div', {}, h('p', { class: 'muted' }, 'Chargement...'));
  const others = h('div');

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
    try {
      const [directory, pending, jobs] = await Promise.all([api.groupDirectory(), api.myInvitations(),
        api.listAnalyses().catch(() => [])]);
      analysesByGroup = jobs;
      mount(invitations, receivedInvitations(pending.received, run));
      const memberOf = directory.filter((g) => g.myRole);
      mount(mine, memberOf.length ? memberOf.map((g) => groupCard(g, run, analysesByGroup))
        : emptyState('Vous n\'appartenez à aucun groupe. Rejoignez un groupe public ou attendez une invitation.'));
      const rest = directory.filter((g) => !g.myRole);
      // Un administrateur gère tous les groupes (sans en devenir membre) ; les autres voient l'annuaire public.
      mount(others, !rest.length ? emptyState('Aucun autre groupe visible.')
        : session.can(PERMISSIONS.MANAGE_GROUPS) ? rest.map((g) => groupCard(g, run, analysesByGroup))
          : directoryTable(rest, pending.sent, run));
    } catch (error) {
      mount(mine, emptyState(error.message));
    }
  }

  mount(container,
    invitations,
    h('section', { class: 'card' }, h('div', { class: 'card-header' }, h('h2', {}, 'Mes groupes')),
      h('p', { class: 'hint' }, 'Les analyses rattachées à un groupe sont visibles de ses membres. Les responsables ',
        'invitent, acceptent les demandes, retirent des membres et peuvent supprimer les analyses du groupe.')),
    mine,
    h('section', { class: 'card' }, h('h2', {}, session.can(PERMISSIONS.MANAGE_GROUPS)
      ? 'Autres groupes' : 'Annuaire des groupes publics'), others),
    createGroupCard(run));
  refresh();
}

function receivedInvitations(received, run) {
  if (!received.length) return null;
  return h('section', { class: 'card highlight-card' },
    h('h2', {}, `Invitations reçues (${received.length})`),
    h('ul', { class: 'invite-list' }, received.map((invitation) => h('li', {},
      h('div', {},
        h('strong', {}, invitation.groupName),
        h('span', { class: 'muted small' }, ` - invité par ${invitation.createdBy}, ${formatDate(invitation.createdAt)}`,
          invitation.manager ? ' - comme responsable' : ''),
        invitation.message ? h('p', { class: 'small prewrap quote' }, invitation.message) : null),
      h('div', { class: 'actions' },
        h('button', { class: 'button primary small', type: 'button',
          onclick: run(() => api.acceptInvitation(invitation.id), `Vous avez rejoint "${invitation.groupName}".`) },
        'Accepter'),
        h('button', { class: 'button ghost small', type: 'button',
          onclick: run(() => api.declineInvitation(invitation.id), 'Invitation déclinée.') }, 'Refuser'))))));
}

/**
 * Synthèse d'un groupe : ce que l'on regarde en réunion d'équipe, et non analyse par analyse.
 *
 * Volontairement construite à partir des analyses déjà chargées : pas d'appel supplémentaire, et la vue
 * reste juste même si un dépôt a été analysé dix fois (seule la dernière analyse de chaque cible compte).
 */
function groupOverview(group, jobs) {
  const analyses = (jobs ?? []).filter((job) => job.groupId === group.id);
  const state = groupSummary(analyses);
  if (!state.repositories) {
    return h('p', { class: 'muted small' }, 'Aucune analyse terminée rattachée à ce groupe : rattachez une '
      + 'analyse au groupe depuis sa page pour alimenter cette synthèse.');
  }
  // Même tuile que le tableau de bord d'une analyse : on ne réinvente pas un affichage pour les mêmes chiffres.
  const tile = (value, label, tone) => statTile(value, label, tone === 'warning' ? 'serious' : tone);
  const progression = state.improved || state.worsened
    ? `${state.improved} dépôt(s) en progrès, ${state.worsened} en recul depuis l'analyse précédente`
    : 'Pas encore de deuxième analyse : la progression apparaîtra ensuite';
  return h('div', { class: 'group-overview' },
    h('div', { class: 'kpis' },
      tile(state.score ?? '-', 'score moyen', state.score == null ? null : scoreTone(state.score)),
      tile(state.repositories, plural(state.repositories, 'dépôt suivi', 'dépôts suivis')),
      tile(state.disallowed, 'actifs interdits', state.disallowed ? 'critical' : null),
      tile(state.deprecated, 'actifs dépréciés', state.deprecated ? 'serious' : null),
      tile(state.quantumVulnerable, 'vulnérables au quantique', state.quantumVulnerable ? 'serious' : null),
      tile(state.knownExploited, 'CVE exploitées (KEV)', state.knownExploited ? 'critical' : null)),
    h('p', { class: 'muted small' }, progression,
      state.lastAnalysisAt ? ` - dernière analyse le ${formatDate(state.lastAnalysisAt)}` : ''),
    h('details', { class: 'group-repositories' },
      h('summary', {}, 'Dépôts, du plus exposé au moins exposé'),
      h('table', { class: 'table' },
        h('thead', {}, h('tr', {}, ['Dépôt', 'Score', 'Interdits', 'Dépréciés', 'Évolution']
          .map((t) => h('th', { scope: 'col' }, t)))),
        h('tbody', {}, state.repositoriesByRisk.map((repo) => h('tr', {},
          h('td', {}, h('a', { href: `#/report/${repo.id}` }, repo.label ?? shortTarget(repo.target)),
            h('div', { class: 'muted small' }, repo.target)),
          h('td', {}, String(repo.score)),
          h('td', {}, String(repo.disallowed)),
          h('td', {}, String(repo.deprecated)),
          h('td', {}, repo.delta == null ? '-'
            : h('span', { class: repo.delta > 0 ? 'delta-up' : repo.delta < 0 ? 'delta-down' : '' },
              `${repo.delta > 0 ? '+' : ''}${repo.delta} pts`))))))));
}

function groupCard(group, run, jobs) {
  const manage = group.myRole === 'manager' || session.can(PERMISSIONS.MANAGE_GROUPS);
  const me = session.current()?.user?.id;
  return h('section', { class: 'card' },
    h('div', { class: 'card-header' },
      h('div', {},
        h('h2', {}, group.name, ' ', badge(ROLE_BADGES[group.myRole ?? 'admin'])),
        h('p', { class: 'muted small' }, visibilityLabel(group.visibility), ` - ${group.memberCount} membre(s)`,
          group.description ? ` - ${group.description}` : '')),
      h('div', { class: 'actions' },
        manage ? h('button', { class: 'button small ghost', type: 'button', onclick: run(async () => {
          if (window.confirm(`Supprimer le groupe "${group.name}" ? Ses analyses deviennent privées (visibles de `
            + 'leur demandeur et des administrateurs).')) {
            await api.deleteGroup(group.id);
          }
        }) }, 'Supprimer') : null,
        group.myRole ? h('button', { class: 'button small ghost', type: 'button', onclick: run(async () => {
          if (window.confirm(`Quitter le groupe "${group.name}" ? Vous ne verrez plus ses analyses.`)) {
            await api.leaveGroup(group.id);
          }
        }) }, 'Quitter') : null)),
    groupOverview(group, jobs),
    h('table', { class: 'table' },
      h('thead', {}, h('tr', {}, ['Membre', 'Rôle', ''].map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', {}, group.members.map((m) => h('tr', {},
        h('td', {}, h('strong', {}, m.displayName ?? m.username), h('span', { class: 'muted small' }, ` ${m.username}`),
          m.userId === me ? h('span', { class: 'tag' }, 'vous') : null),
        h('td', {}, manage && m.userId !== me ? h('label', { class: 'inline-check' }, h('input', {
          type: 'checkbox', checked: m.manager,
          onchange: run(() => api.setGroupManager(group.id, m.userId, !m.manager)),
        }), ' Responsable') : (m.manager ? 'Responsable' : 'Membre')),
        h('td', { class: 'actions' }, manage && m.userId !== me ? h('button', {
          class: 'button small ghost', type: 'button',
          onclick: run(async () => {
            if (window.confirm(`Retirer ${m.username} du groupe ?`)) await api.removeGroupMember(group.id, m.userId);
          }),
        }, 'Retirer') : null))))),
    manage ? managerTools(group, run) : null);
}

function managerTools(group, run) {
  const username = h('input', { 'aria-label': 'Identifiant à inviter', placeholder: 'Identifiant du compte',
    autocomplete: 'off', required: true });
  const message = h('input', { 'aria-label': 'Message (facultatif)', placeholder: 'Message (facultatif)',
    maxlength: 500 });
  const manager = h('input', { type: 'checkbox' });
  const pending = group.pending ?? [];
  const requests = pending.filter((p) => p.kind === 'join-request');
  const invitations = pending.filter((p) => p.kind === 'invitation');
  return h('div', { class: 'manager-tools' },
    requests.length ? h('div', {}, h('h3', {}, `Demandes d'adhésion (${requests.length})`),
      h('ul', { class: 'invite-list' }, requests.map((r) => h('li', {},
        h('div', {}, h('strong', {}, r.username), h('span', { class: 'muted small' }, ` - ${formatDate(r.createdAt)}`),
          r.message ? h('p', { class: 'small prewrap quote' }, r.message) : null),
        h('div', { class: 'actions' },
          h('button', { class: 'button primary small', type: 'button',
            onclick: run(() => api.acceptInvitation(r.id), `${r.username} a rejoint le groupe.`) }, 'Accepter'),
          h('button', { class: 'button ghost small', type: 'button',
            onclick: run(() => api.declineInvitation(r.id), 'Demande refusée.') }, 'Refuser')))))) : null,
    h('h3', {}, 'Inviter un utilisateur'),
    h('form', {
      class: 'filters',
      onsubmit: async (event) => {
        event.preventDefault();
        await run(() => api.inviteToGroup(group.id, username.value.trim(), manager.checked,
          message.value.trim() || null), `Invitation envoyée à ${username.value.trim()} : elle doit l'accepter.`)();
      },
    }, username, message, h('label', { class: 'inline-check' }, manager, ' comme responsable'),
    h('button', { class: 'button small', type: 'submit' }, 'Inviter')),
    invitations.length ? h('div', {}, h('p', { class: 'muted small' }, 'Invitations en attente de réponse :'),
      h('ul', { class: 'chip-list' }, invitations.map((i) => h('li', { class: 'chip' }, i.username,
        h('button', { class: 'chip-remove', type: 'button', 'aria-label': `Annuler l'invitation de ${i.username}`,
          title: 'Annuler l\'invitation', onclick: run(() => api.cancelInvitation(i.id), 'Invitation annulée.') }, '✕')))))
      : null,
    editGroupForm(group, run));
}

function editGroupForm(group, run) {
  const name = h('input', { value: group.name, maxlength: 100, 'aria-label': 'Nom du groupe', required: true });
  const description = h('input', { value: group.description ?? '', maxlength: 500, 'aria-label': 'Description' });
  const visibility = visibilitySelect(group.visibility, `Visibilité de ${group.name}`);
  return h('details', { class: 'group-settings' }, h('summary', {}, 'Modifier le groupe'),
    h('form', {
      class: 'form-grid',
      onsubmit: async (event) => {
        event.preventDefault();
        await run(() => api.updateGroup(group.id, { name: name.value.trim(), description: description.value.trim(),
          visibility: visibility.value }), 'Groupe mis à jour.')();
      },
    }, name, description, visibility,
    h('div', { class: 'actions' }, h('button', { class: 'button small', type: 'submit' }, 'Enregistrer'))));
}

function directoryTable(groups, sent, run) {
  const requested = new Set(sent.map((s) => s.groupId));
  return h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
    h('thead', {}, h('tr', {}, ['Groupe', 'Visibilité', 'Membres', ''].map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, groups.map((g) => {
      const pendingRequest = sent.find((s) => s.groupId === g.id);
      return h('tr', {},
        h('td', {}, h('strong', {}, g.name), g.description ? h('div', { class: 'muted small' }, g.description) : null),
        h('td', {}, visibilityLabel(g.visibility)),
        h('td', {}, String(g.memberCount)),
        h('td', { class: 'actions' },
          g.joinRequested || requested.has(g.id)
            ? [h('span', { class: 'muted small' }, 'Demande envoyée'), pendingRequest ? h('button', {
              class: 'button small ghost', type: 'button',
              onclick: run(() => api.cancelInvitation(pendingRequest.id), 'Demande annulée.'),
            }, 'Annuler') : null]
            : g.visibility === 'public' ? h('button', {
              class: 'button small', type: 'button',
              onclick: run(() => {
                const message = window.prompt(`Message aux responsables de "${g.name}" (facultatif) :`, '');
                if (message === null) return Promise.resolve();
                return api.requestToJoin(g.id, message.trim() || null);
              }, 'Demande envoyée aux responsables.'),
            }, 'Demander à rejoindre') : null));
    }))));
}

function createGroupCard(run) {
  const name = h('input', { id: 'group-name', required: true, maxlength: 100 });
  const description = h('input', { id: 'group-description', maxlength: 500 });
  const visibility = visibilitySelect('private', 'Visibilité', 'group-visibility');
  return h('section', { class: 'card' }, h('h2', {}, 'Créer un groupe'),
    h('form', {
      class: 'form-grid',
      onsubmit: async (event) => {
        event.preventDefault();
        const form = event.target;
        await run(async () => {
          await api.createGroup({ name: name.value.trim(), description: description.value.trim() || null,
            visibility: visibility.value });
          form.reset();
        }, 'Groupe créé : vous en êtes responsable.')();
      },
    },
    h('div', { class: 'field' }, h('label', { for: 'group-name' }, 'Nom'), name),
    h('div', { class: 'field' }, h('label', { for: 'group-description' }, 'Description'), description),
    h('div', { class: 'field' }, h('label', { for: 'group-visibility' }, 'Visibilité'), visibility),
    h('div', { class: 'actions' }, h('button', { class: 'button primary', type: 'submit' }, 'Créer'))),
    h('p', { class: 'hint' }, VISIBILITIES.map((v) => `${v.label} : ${v.description}`).join(' - '),
      '. Selon les paramètres, la création peut être réservée aux administrateurs.'));
}

function visibilitySelect(value, label, idAttr) {
  return h('select', { id: idAttr, 'aria-label': label },
    VISIBILITIES.map((v) => h('option', { value: v.id, selected: v.id === value }, v.label)));
}

function visibilityLabel(visibility) {
  return VISIBILITIES.find((v) => v.id === visibility)?.label ?? visibility;
}
