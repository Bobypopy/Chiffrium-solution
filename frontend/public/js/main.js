// Point d'entrée : authentification puis routeur par fragment d'URL
// (#/analyses, #/report/<id>/<onglet>/<actif>, #/compare/<réf>/<cible>, #/catalog, #/groups, #/me, #/help,
//  #/admin/<onglet>, #/about, #/login, #/password, #/sso/<ticket>).

import { api, onAuthRequired } from './api.js';
import { LOCALES, initLocale, locale, onLocaleChange, setContext, setLocale, t } from './i18n.js';
import { PERMISSIONS, session } from './session.js';
import { h, mount, toast } from './ui/dom.js';
import { notificationBell } from './ui/notifications.js';
import { setupUpdates } from './ui/updates.js';
import { renderAbout } from './views/aboutView.js';
import { renderAdmin } from './views/adminView.js';
import { renderAnalyses } from './views/analysesView.js';
import { renderCatalog } from './views/catalogView.js';
import { renderCompare } from './views/compareView.js';
import { renderGroups } from './views/groupsView.js';
import { renderHelp } from './views/helpView.js';
import { completeSso, renderChangePassword, renderLogin } from './views/loginView.js';
import { renderMe } from './views/meView.js';
import { renderReport } from './views/reportView.js';

const THEME_KEY = 'chiffrium.theme';
/** Pages accessibles sans session. */
const PUBLIC_PAGES = new Set(['login', 'sso', 'about', 'help']);
const ADMIN_PERMISSIONS = [PERMISSIONS.MANAGE_USERS, PERMISSIONS.VIEW_AUDIT, PERMISSIONS.MANAGE_SETTINGS,
  PERMISSIONS.MANAGE_GROUPS];
const app = document.getElementById('app');
const nav = document.getElementById('main-nav');
const userArea = document.getElementById('user-area');
const bell = notificationBell();
let cleanup = null;
let info = null;
let bellActive = false;

function parseHash() {
  const [path, query = ''] = location.hash.replace(/^#\/?/, '').split('?');
  const [page, ...rest] = path.split('/');
  return { page: page || 'analyses', rest, params: new URLSearchParams(query) };
}

function goHome() {
  if (location.hash === '#/analyses') route();
  else location.hash = '#/analyses';
}

async function loadProfile() {
  session.update(await api.me());
  if (!info) {
    try {
      info = await api.info();
      document.getElementById('version').textContent = `v${info.version}`;
    } catch {
      // Informations facultatives (ex. mot de passe provisoire à changer d'abord).
    }
  }
}

async function route() {
  if (typeof cleanup === 'function') cleanup();
  cleanup = null;
  const { page, rest, params } = parseHash();

  if (!PUBLIC_PAGES.has(page) && !session.current()) {
    if (!session.token()) {
      await renderLogin(app, { onDone: afterLogin, ssoFailed: params.get('sso') === 'echec' });
      return;
    }
    try {
      await loadProfile();
    } catch {
      session.close();
      await renderLogin(app, { onDone: afterLogin });
      return;
    }
  }
  if (session.current()?.user?.mustChangePassword && page !== 'password') {
    location.hash = '#/password';
    return;
  }

  // Quelques mots dépendent de l'écran (voir i18n/ui/contextes.js) : on le dit avant de dessiner.
  setContext(page);
  for (const link of document.querySelectorAll('[data-nav]')) {
    link.setAttribute('aria-current', link.dataset.nav === page ? 'page' : 'false');
  }
  switch (page) {
    case 'login':
      if (session.current()) goHome();
      else await renderLogin(app, { onDone: afterLogin, ssoFailed: params.get('sso') === 'echec' });
      break;
    case 'sso':
      await completeSso(app, rest[0], { onDone: afterLogin });
      break;
    case 'password':
      renderChangePassword(app, { onDone: afterLogin, forced: Boolean(session.current()?.user?.mustChangePassword) });
      break;
    case 'report':
      await renderReport(app, { id: rest[0], tab: rest[1] || 'dashboard',
        selection: rest[2] ? decodeURIComponent(rest.slice(2).join('/')) : null });
      break;
    case 'catalog':
      await renderCatalog(app);
      break;
    case 'compare':
      await renderCompare(app, { baseId: rest[0], targetId: rest[1] });
      break;
    case 'about':
      await renderAbout(app);
      break;
    case 'groups':
      await renderGroups(app);
      break;
    case 'help':
      renderHelp(app);
      break;
    case 'me':
      await renderMe(app);
      break;
    case 'admin':
      renderAdmin(app, { tab: rest[0] });
      break;
    default:
      cleanup = renderAnalyses(app, { info });
  }
  if (bellActive) bell.refresh();
  app.focus({ preventScroll: true });
}

async function afterLogin() {
  await loadProfile().catch(() => {});
  goHome();
}

function renderChrome(current) {
  nav.hidden = !current;
  const admin = nav.querySelector('[data-nav="admin"]');
  if (admin) admin.hidden = !ADMIN_PERMISSIONS.some((p) => session.can(p));
  if (!current) {
    bell.stop();
    bellActive = false;
    mount(userArea);
    return;
  }
  const { user } = current;
  if (!bellActive && !user.mustChangePassword) {
    bellActive = true;
    bell.start();
  }
  mount(userArea,
    bellActive ? bell.element : null,
    h('a', { class: 'user-name', href: '#/me', title: `Mon espace - ${user.username} - rôle ${user.role}` },
      user.displayName),
    h('button', {
      class: 'button ghost small', type: 'button',
      onclick: async () => {
        try {
          await api.logout();
        } catch {
          // Session déjà expirée côté serveur : on ferme localement.
        }
        session.close();
        location.hash = '#/login';
        toast('Déconnecté.', 'good');
      },
    }, 'Déconnexion'));
}

function setupTheme() {
  const toggle = document.getElementById('theme-toggle');
  const systemDark = () => matchMedia('(prefers-color-scheme: dark)').matches;
  const isDark = () => document.documentElement.dataset.theme === 'dark'
    || (!document.documentElement.dataset.theme && systemDark());
  const apply = (theme) => {
    if (theme) document.documentElement.dataset.theme = theme;
    else delete document.documentElement.dataset.theme;
    const label = isDark() ? 'Passer au thème clair' : 'Passer au thème sombre';
    toggle.textContent = isDark() ? '☀' : '☾';
    toggle.title = label;
    toggle.setAttribute('aria-label', label);
  };
  let stored = null;
  try {
    stored = localStorage.getItem(THEME_KEY);
  } catch {
    // Stockage indisponible (navigation privée) : thème du système.
  }
  apply(stored);
  toggle.addEventListener('click', () => {
    const next = isDark() ? 'light' : 'dark';
    apply(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      // Préférence non mémorisée : sans conséquence.
    }
  });
}

/**
 * Textes de la page d'accueil HTML (navigation, liens d'accès) : ils ne passent pas par `h()`, donc on les
 * traduit ici, à l'initialisation et à chaque changement de langue.
 */
function translateChrome() {
  for (const element of document.querySelectorAll('[data-i18n]')) {
    if (!element.dataset.fr) element.dataset.fr = element.textContent;
    element.textContent = t(element.dataset.fr);
  }
  for (const element of document.querySelectorAll('[data-i18n-label]')) {
    if (!element.dataset.frLabel) element.dataset.frLabel = element.getAttribute('aria-label') ?? '';
    element.setAttribute('aria-label', t(element.dataset.frLabel));
  }
}

function setupLocale() {
  initLocale();
  const select = document.getElementById('locale-select');
  mount(select, LOCALES.map((l) => h('option', { value: l.id, selected: l.id === locale(), title: l.title },
    l.label)));
  select.addEventListener('change', () => setLocale(select.value));
  onLocaleChange(() => {
    translateChrome();
    renderChrome(session.current());
    route();
  });
  translateChrome();
}

function start() {
  setupLocale();
  setupTheme();
  setupUpdates();
  session.onChange(renderChrome);
  renderChrome(null);
  onAuthRequired((reason) => {
    if (reason === 'password') {
      location.hash = '#/password';
    } else {
      toast('Session expirée : reconnectez-vous.', 'serious');
      location.hash = '#/login';
      route();
    }
  });
  window.addEventListener('hashchange', route);
  // Le routeur a pris la main : le filet de sécurité de demarrage.js n'a plus lieu d'être.
  window.__demarrageOk?.();
  route().catch((error) => mount(app, h('section', { class: 'card error-box' }, h('h2', {}, 'Erreur'),
    h('p', {}, error.message))));
}

start();
