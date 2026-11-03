import { api } from '../api.js';
import { session } from '../session.js';
import { h, mount, toast } from '../ui/dom.js';
import { usageNotice } from './aboutView.js';

/** Doit rester aligné sur PasswordPolicy.MIN_LENGTH côté serveur (le serveur reste l'autorité). */
export const MIN_PASSWORD_LENGTH = 12;

function field(id, text, input, hint = null) {
  return h('div', { class: 'field' }, h('label', { for: id }, text), input,
    hint ? h('span', { class: 'muted small' }, hint) : null);
}

function passwordInput(id, autocomplete) {
  return h('input', { id, type: 'password', required: true, autocomplete, minlength: MIN_PASSWORD_LENGTH });
}

function errorBox() {
  return h('p', { class: 'error-text', role: 'alert' });
}

/** Ouvre la session puis charge le profil (rôle, permissions). */
async function openSession(result, onDone) {
  session.open(result.token);
  session.update(await api.me());
  onDone();
}

/**
 * Écran de connexion. Si aucun compte n'existe, propose la création du premier administrateur
 * (jeton d'installation affiché dans les journaux du serveur, ou fourni automatiquement par l'application
 * de bureau).
 */
export async function renderLogin(container, { onDone, ssoFailed = false }) {
  let status = { setupRequired: false, oidcEnabled: false };
  try {
    status = await api.authStatus();
  } catch (error) {
    mount(container, h('section', { class: 'card auth-card error-box' }, h('h2', {}, 'Serveur injoignable'),
      h('p', {}, error.message)));
    return;
  }
  const notice = h('div');
  mount(container, status.setupRequired ? setupForm(onDone) : loginForm(status, onDone, ssoFailed), notice,
    h('p', { class: 'auth-links' }, h('a', { href: '#/about' }, 'À propos, licences et confidentialité')));
  usageNotice().then((text) => {
    if (text) mount(notice, h('section', { class: 'card auth-card notice' }, h('h2', {}, 'Charte d\'utilisation'),
      h('p', { class: 'prewrap' }, text)));
  });
}

function loginForm(status, onDone, ssoFailed) {
  const username = h('input', { id: 'login-user', required: true, autocomplete: 'username', autofocus: true });
  const password = h('input', { id: 'login-password', type: 'password', required: true,
    autocomplete: 'current-password' });
  const error = errorBox();
  const submit = h('button', { class: 'button primary', type: 'submit' }, 'Se connecter');
  if (ssoFailed) error.textContent = 'La connexion par authentification unique a échoué ou a été refusée.';

  return h('section', { class: 'card auth-card' },
    h('h1', {}, 'Connexion'),
    h('form', {
      onsubmit: async (event) => {
        event.preventDefault();
        submit.disabled = true;
        error.textContent = '';
        try {
          await openSession(await api.login(username.value.trim(), password.value), onDone);
        } catch (e) {
          error.textContent = e.message;
          password.value = '';
        } finally {
          submit.disabled = false;
        }
      },
    },
    field('login-user', 'Identifiant', username),
    field('login-password', 'Mot de passe', password),
    error,
    h('div', { class: 'actions' }, submit)),
    status.oidcEnabled ? h('div', { class: 'sso-block' },
      h('p', { class: 'muted small' }, 'ou'),
      h('button', {
        class: 'button', type: 'button',
        onclick: async () => {
          try {
            const { authorizationUrl } = await api.ssoStart();
            location.assign(authorizationUrl);
          } catch (e) {
            error.textContent = e.message;
          }
        },
      }, 'Se connecter avec l\'authentification unique (SSO)')) : null);
}

function setupForm(onDone) {
  const token = h('input', { id: 'setup-token', required: true, autocomplete: 'off', spellcheck: 'false' });
  const username = h('input', { id: 'setup-user', required: true, autocomplete: 'username', value: 'admin' });
  const displayName = h('input', { id: 'setup-name', autocomplete: 'name' });
  const password = passwordInput('setup-password', 'new-password');
  const confirm = passwordInput('setup-confirm', 'new-password');
  const error = errorBox();
  const submit = h('button', { class: 'button primary', type: 'submit' }, 'Créer le compte administrateur');
  // Application de bureau : le jeton est lu localement par le processus principal (poste de l'utilisateur).
  window.desktop?.setupToken?.().then((value) => {
    if (value && !token.value) token.value = value;
  }).catch(() => {});

  return h('section', { class: 'card auth-card' },
    h('h1', {}, 'Première installation'),
    h('p', { class: 'hint' }, 'Aucun compte n\'existe encore. Le jeton d\'installation figure dans le journal du ',
      'serveur et dans le fichier data/secrets/setup-token (droits restreints). Il est détruit après usage.'),
    h('form', {
      onsubmit: async (event) => {
        event.preventDefault();
        error.textContent = '';
        if (password.value !== confirm.value) {
          error.textContent = 'Les deux mots de passe diffèrent.';
          return;
        }
        submit.disabled = true;
        try {
          await openSession(await api.setup({
            setupToken: token.value.trim(), username: username.value.trim(),
            password: password.value, displayName: displayName.value.trim() || null,
          }), onDone);
          toast('Compte administrateur créé.', 'good');
        } catch (e) {
          error.textContent = e.message;
        } finally {
          submit.disabled = false;
        }
      },
    },
    field('setup-token', 'Jeton d\'installation', token),
    field('setup-user', 'Identifiant', username),
    field('setup-name', 'Nom affiché', displayName),
    field('setup-password', 'Mot de passe', password,
      `Au moins ${MIN_PASSWORD_LENGTH} caractères ; une phrase de passe est idéale.`),
    field('setup-confirm', 'Confirmation', confirm),
    error,
    h('div', { class: 'actions' }, submit)));
}

/** Changement de mot de passe (obligatoire après un mot de passe provisoire). */
export function renderChangePassword(container, { onDone, forced }) {
  const current = h('input', { id: 'pwd-current', type: 'password', required: true, autocomplete: 'current-password' });
  const next = passwordInput('pwd-new', 'new-password');
  const confirm = passwordInput('pwd-confirm', 'new-password');
  const error = errorBox();
  const submit = h('button', { class: 'button primary', type: 'submit' }, 'Changer le mot de passe');
  mount(container, h('section', { class: 'card auth-card' },
    h('h1', {}, 'Changer le mot de passe'),
    forced ? h('p', { class: 'hint' }, 'Votre mot de passe est provisoire : choisissez-en un nouveau pour continuer.')
      : null,
    h('form', {
      onsubmit: async (event) => {
        event.preventDefault();
        error.textContent = '';
        if (next.value !== confirm.value) {
          error.textContent = 'Les deux mots de passe diffèrent.';
          return;
        }
        submit.disabled = true;
        try {
          await openSession(await api.changePassword(current.value, next.value), onDone);
          toast('Mot de passe modifié. Vos autres sessions ont été fermées.', 'good');
        } catch (e) {
          error.textContent = e.message;
        } finally {
          submit.disabled = false;
        }
      },
    },
    field('pwd-current', 'Mot de passe actuel', current),
    field('pwd-new', 'Nouveau mot de passe', next, `Au moins ${MIN_PASSWORD_LENGTH} caractères.`),
    field('pwd-confirm', 'Confirmation', confirm),
    error,
    h('div', { class: 'actions' }, submit,
      forced ? null : h('a', { class: 'button ghost', href: '#/analyses' }, 'Annuler')))));
}

/** Retour de l'authentification unique : le ticket éphémère est échangé contre une session. */
export async function completeSso(container, ticket, { onDone }) {
  mount(container, h('p', { class: 'muted' }, 'Connexion en cours...'));
  try {
    await openSession(await api.ssoExchange(ticket), onDone);
  } catch {
    location.hash = '#/login?sso=echec';
  }
}
