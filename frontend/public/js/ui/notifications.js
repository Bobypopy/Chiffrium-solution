// Notifications internes : cloche dans l'en-tête (compteur rafraîchi périodiquement) et liste réutilisable.
// Les alertes vers un canal d'équipe (Slack, Teams, Discord...) sont envoyées par le serveur, pas par le navigateur.

import { api } from '../api.js';
import { formatDate } from '../domain/format.js';
import { emptyState, h, mount, toast } from './dom.js';

const POLL_INTERVAL_MS = 30_000;
const PANEL_SIZE = 8;
// Glyphes monochromes, comme les badges de statut : une notification n'est pas une conversation.
const KIND_ICONS = {
  GROUP_INVITATION: '✉',
  GROUP_JOIN_REQUEST: '?',
  GROUP_MEMBERSHIP: '✓',
  CATALOG_REQUEST: '!',
  ANALYSIS_FINISHED: '✓',
  ACCOUNT: 'i',
};

/** Liste de notifications ; un clic marque comme lue et suit le lien éventuel. */
export function notificationList(notifications, { onChange, limit } = {}) {
  const items = limit ? notifications.slice(0, limit) : notifications;
  if (!items.length) return emptyState('Aucune notification.');
  return h('ul', { class: 'notification-list' }, items.map((n) => h('li', { class: n.readAt ? 'read' : 'unread' },
    h('button', {
      type: 'button', class: 'notification',
      onclick: async () => {
        try {
          if (!n.readAt) await api.markNotificationsRead([n.id]);
        } catch (error) {
          toast(error.message, 'critical');
        }
        if (n.link) location.hash = n.link;
        onChange?.();
      },
    },
    h('span', { class: 'notification-icon', 'aria-hidden': 'true' }, KIND_ICONS[n.kind] ?? '•'),
    h('span', { class: 'notification-text' },
      h('strong', {}, n.title),
      n.body ? h('span', { class: 'small muted prewrap' }, n.body) : null,
      h('span', { class: 'small muted' }, formatDate(n.createdAt), n.readAt ? '' : ' - non lue'))))));
}

/**
 * Cloche de l'en-tête : compteur des non-lues, panneau des dernières notifications.
 * @returns {{ element: HTMLElement, start: () => void, stop: () => void }}
 */
export function notificationBell() {
  const count = h('span', { class: 'bell-count', hidden: true });
  const button = h('button', { class: 'button ghost small bell', type: 'button', 'aria-expanded': 'false',
    'aria-haspopup': 'true', title: 'Notifications' }, h('span', { 'aria-hidden': 'true' }, '✉'),
  h('span', { class: 'visually-hidden' }, 'Notifications'), count);
  const panel = h('div', { class: 'notification-panel card', hidden: true, role: 'dialog',
    'aria-label': 'Notifications' });
  const element = h('div', { class: 'bell-area' }, button, panel);
  let timer = null;
  let last = 0;
  let primed = false;

  const setCount = (unread) => {
    count.hidden = unread === 0;
    count.textContent = unread > 99 ? '99+' : String(unread);
    button.setAttribute('aria-label', `Notifications : ${unread} non lue(s)`);
    last = unread;
  };

  const poll = async () => {
    clearTimeout(timer);
    try {
      const { unread } = await api.unreadNotifications();
      if (primed && unread > last) toast('Nouvelle notification : voir la cloche en haut de page.', 'neutral');
      primed = true;
      setCount(unread);
    } catch {
      // Hors ligne ou session expirée : le gestionnaire d'authentification s'en charge.
    }
    timer = setTimeout(poll, POLL_INTERVAL_MS);
  };

  const close = () => {
    panel.hidden = true;
    button.setAttribute('aria-expanded', 'false');
  };

  const open = async () => {
    panel.hidden = false;
    button.setAttribute('aria-expanded', 'true');
    mount(panel, h('p', { class: 'muted' }, 'Chargement...'));
    try {
      const list = await api.listNotifications();
      mount(panel,
        h('div', { class: 'card-header' }, h('h2', {}, 'Notifications'),
          h('button', { class: 'button ghost small', type: 'button', onclick: async () => {
            await api.markNotificationsRead(null).catch((e) => toast(e.message, 'critical'));
            poll();
            open();
          } }, 'Tout marquer comme lu')),
        notificationList(list, { limit: PANEL_SIZE, onChange: () => { close(); poll(); } }),
        h('a', { class: 'small', href: '#/me', onclick: close }, 'Tout voir dans Mon espace'));
    } catch (error) {
      mount(panel, emptyState(error.message));
    }
  };

  button.addEventListener('click', () => (panel.hidden ? open() : close()));
  document.addEventListener('click', (event) => {
    if (!element.contains(event.target)) close();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !panel.hidden) {
      close();
      button.focus();
    }
  });

  return {
    element,
    start: () => { primed = false; poll(); },
    stop: () => { clearTimeout(timer); close(); setCount(0); },
    refresh: poll,
  };
}
