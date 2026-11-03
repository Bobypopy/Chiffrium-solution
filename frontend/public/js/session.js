// Session de l'utilisateur connecté. Le jeton est gardé en sessionStorage : il disparaît à la fermeture de
// l'onglet (ou de l'application de bureau) et n'est jamais placé dans une URL ni dans un cookie.

const TOKEN_KEY = 'chiffrium.session';
const listeners = new Set();
let token = null;
let current = null;

function read() {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function write(value) {
  try {
    if (value) sessionStorage.setItem(TOKEN_KEY, value);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // Stockage indisponible : la session ne survivra pas au rechargement, sans autre conséquence.
  }
}

token = read();

export const session = {
  token: () => token,

  /** Utilisateur courant ({ user, permissions }) ou null. */
  current: () => current,

  can: (permission) => Boolean(current?.permissions?.includes(permission)),

  open(newToken, me = null) {
    token = newToken;
    write(newToken);
    if (me) this.update(me);
  },

  update(me) {
    current = me;
    listeners.forEach((listener) => listener(current));
  },

  close() {
    token = null;
    current = null;
    write(null);
    listeners.forEach((listener) => listener(null));
  },

  onChange(listener) {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
};

/** Permissions exposées par l'API (voir Permission côté serveur). */
export const PERMISSIONS = Object.freeze({
  VIEW_REPORTS: 'VIEW_REPORTS',
  RUN_ANALYSIS: 'RUN_ANALYSIS',
  DELETE_OWN_ANALYSIS: 'DELETE_OWN_ANALYSIS',
  DELETE_ANY_ANALYSIS: 'DELETE_ANY_ANALYSIS',
  EDIT_CATALOG: 'EDIT_CATALOG',
  MANAGE_USERS: 'MANAGE_USERS',
  MANAGE_SETTINGS: 'MANAGE_SETTINGS',
  VIEW_AUDIT: 'VIEW_AUDIT',
  VIEW_ALL_ANALYSES: 'VIEW_ALL_ANALYSES',
  REQUEST_CATALOG_CHANGE: 'REQUEST_CATALOG_CHANGE',
  MANAGE_GROUPS: 'MANAGE_GROUPS',
});
