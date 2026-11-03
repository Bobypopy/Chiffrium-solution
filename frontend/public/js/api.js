// Client de l'API REST du backend. Chemins relatifs : le frontend et l'API partagent la même origine
// (nginx, ou le backend lui-même dans l'application de bureau), donc aucune URL n'est codée en dur.

import { session } from './session.js';

const BASE = 'api';
const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN = 403;
const PASSWORD_CHANGE_REQUIRED = 'PASSWORD_CHANGE_REQUIRED';

export class ApiError extends Error {
  constructor(message, status, details = [], code = null) {
    super(message);
    this.status = status;
    this.details = details;
    this.code = code;
  }
}

/** Abonnés prévenus quand la session expire ou qu'un changement de mot de passe est exigé. */
const authListeners = new Set();
export function onAuthRequired(listener) {
  authListeners.add(listener);
}

async function send(path, { method = 'GET', body, raw = false } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (session.token()) headers.Authorization = `Bearer ${session.token()}`;
  let response;
  try {
    response = await fetch(`${BASE}${path}`, {
      method, headers, body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (error) {
    throw new ApiError(`Serveur injoignable : ${error.message}`, 0);
  }
  if (!response.ok) {
    let payload = {};
    try {
      payload = await response.json();
    } catch {
      // Corps non JSON : on garde le message générique.
    }
    const error = new ApiError(payload.error ?? `Erreur HTTP ${response.status}`, response.status,
      payload.details ?? [], payload.code ?? null);
    if (response.status === HTTP_UNAUTHORIZED && session.token()) {
      session.close();
      authListeners.forEach((listener) => listener('login'));
    } else if (response.status === HTTP_FORBIDDEN && error.code === PASSWORD_CHANGE_REQUIRED) {
      authListeners.forEach((listener) => listener('password'));
    }
    throw error;
  }
  return response;
}

async function request(path, options = {}) {
  const response = await send(path, options);
  if (response.status === 204) return null;
  return options.expect === 'text' ? response.text() : response.json();
}

/** Nom proposé par le serveur (Content-Disposition), sinon le nom par défaut. */
function serverFileName(response, fallback) {
  const match = /filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') ?? '');
  return match ? match[1] : fallback;
}

/** Téléchargement authentifié : un lien <a href> ne transmettrait pas le jeton. */
async function download(path, fileName) {
  const response = await send(path);
  const url = URL.createObjectURL(await response.blob());
  const link = Object.assign(document.createElement('a'), { href: url, download: serverFileName(response, fileName) });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

const id = encodeURIComponent;

export const api = {
  // Authentification
  authStatus: () => request('/auth/status'),
  login: (username, password) => request('/auth/login', { method: 'POST', body: { username, password } }),
  setup: (payload) => request('/auth/setup', { method: 'POST', body: payload }),
  me: () => request('/auth/me'),
  logout: () => request('/auth/logout', { method: 'POST' }),
  changePassword: (currentPassword, newPassword) => request('/auth/change-password',
    { method: 'POST', body: { currentPassword, newPassword } }),
  ssoStart: () => request('/auth/oidc/start'),
  ssoExchange: (ticket) => request('/auth/oidc/exchange', { method: 'POST', body: { ticket } }),

  // Analyses
  info: () => request('/info'),
  listAnalyses: () => request('/analyses'),
  getAnalysis: (analysisId) => request(`/analyses/${id(analysisId)}`),
  submitAnalyses: (submission) => request('/analyses', { method: 'POST', body: submission }),
  deleteAnalysis: (analysisId) => request(`/analyses/${id(analysisId)}`, { method: 'DELETE' }),
  cancelAnalysis: (analysisId) => request(`/analyses/${id(analysisId)}/cancel`, { method: 'POST' }),
  rerunAnalysis: (analysisId) => request(`/analyses/${id(analysisId)}/rerun`, { method: 'POST' }),
  shareAnalysis: (analysisId, groupId) => request(`/analyses/${id(analysisId)}/group`,
    { method: 'PUT', body: { groupId } }),
  labelAnalysis: (analysisId, label) => request(`/analyses/${id(analysisId)}/label`,
    { method: 'PUT', body: { label } }),
  getReport: (analysisId) => request(`/analyses/${id(analysisId)}/report`),
  getLog: (analysisId) => request(`/analyses/${id(analysisId)}/log`, { expect: 'text' }),
  downloadCbom: (analysisId) => download(`/analyses/${id(analysisId)}/cbom`, `cbom-${analysisId}.json`),
  downloadSarif: (analysisId) => download(`/analyses/${id(analysisId)}/sarif`, `chiffrium-${analysisId}.sarif`),
  downloadReport: (analysisId) => download(`/analyses/${id(analysisId)}/report?download=true`, `rapport-${analysisId}.json`),
  downloadLog: (analysisId) => download(`/analyses/${id(analysisId)}/log?download=true`, `journal-${analysisId}.log`),
  downloadBundle: (analysisId) => download(`/analyses/${id(analysisId)}/bundle`, `chiffrium-${analysisId}.zip`),

  compareAnalyses: (baseId, targetId) => request(`/analyses/${id(baseId)}/compare/${id(targetId)}`),
  listFavorites: () => request('/favorites'),
  setFavorite: (analysisId, favorite) => request(`/analyses/${id(analysisId)}/favorite`,
    { method: favorite ? 'PUT' : 'DELETE' }),
  about: () => request('/about'),

  // Groupes (adhésion consentie : invitation acceptée par l'invité, demande acceptée par un responsable)
  myGroups: () => request('/me/groups'),
  groupDirectory: () => request('/groups'),
  createGroup: (group) => request('/groups', { method: 'POST', body: group }),
  updateGroup: (groupId, group) => request(`/groups/${id(groupId)}`, { method: 'PATCH', body: group }),
  deleteGroup: (groupId) => request(`/groups/${id(groupId)}`, { method: 'DELETE' }),
  inviteToGroup: (groupId, username, manager, message) => request(`/groups/${id(groupId)}/invitations`,
    { method: 'POST', body: { username, manager, message } }),
  requestToJoin: (groupId, message) => request(`/groups/${id(groupId)}/join`, { method: 'POST', body: { message } }),
  leaveGroup: (groupId) => request(`/groups/${id(groupId)}/leave`, { method: 'POST' }),
  removeGroupMember: (groupId, userId) => request(`/groups/${id(groupId)}/members/${id(userId)}`,
    { method: 'DELETE' }),
  setGroupManager: (groupId, userId, manager) => request(`/groups/${id(groupId)}/members/${id(userId)}/manager`,
    { method: 'PUT', body: { manager } }),
  acceptInvitation: (invitationId) => request(`/invitations/${id(invitationId)}/accept`, { method: 'POST' }),
  declineInvitation: (invitationId) => request(`/invitations/${id(invitationId)}/decline`, { method: 'POST' }),
  cancelInvitation: (invitationId) => request(`/invitations/${id(invitationId)}/cancel`, { method: 'POST' }),
  myInvitations: () => request('/me/invitations'),

  // Espace personnel et notifications
  updateProfile: (profile) => request('/me/profile', { method: 'PATCH', body: profile }),
  exportMyData: () => download('/me/export', 'mes-donnees-chiffrium.json'),
  listNotifications: (unreadOnly = false) => request(`/notifications${unreadOnly ? '?unread=true' : ''}`),
  unreadNotifications: () => request('/notifications/count'),
  markNotificationsRead: (ids = null) => request('/notifications/read', { method: 'POST', body: { ids } }),

  // Catalogue
  getCatalog: () => request('/catalog'),
  catalogReferenceOids: () => request('/catalog/reference-oids'),
  listCatalogRequests: () => request('/catalog/requests'),
  submitCatalogRequest: (payload) => request('/catalog/requests', { method: 'POST', body: payload }),
  withdrawCatalogRequest: (requestId) => request(`/catalog/requests/${id(requestId)}/withdraw`, { method: 'POST' }),
  reviewCatalogRequest: (requestId, approve, comment) => request(`/catalog/requests/${id(requestId)}/review`,
    { method: 'POST', body: { approve, comment } }),
  saveAlgorithm: (definition) => request(`/catalog/algorithms/${id(definition.id)}`, { method: 'PUT', body: definition }),
  deleteAlgorithm: (algorithmId) => request(`/catalog/algorithms/${id(algorithmId)}`, { method: 'DELETE' }),
  importCatalog: (catalog) => request('/catalog', { method: 'PUT', body: catalog }),
  /** Fige le catalogue courant comme politique d'entreprise (numéro de version + empreinte). */
  publishCatalog: (name) => request('/catalog/publish', { method: 'POST', body: { name } }),
  exportCatalog: () => download('/catalog/export', 'catalogue-algorithmes.json'),

  // Administration
  adminOverview: () => request('/admin/overview'),
  listUsers: () => request('/admin/users'),
  createUser: (user) => request('/admin/users', { method: 'POST', body: user }),
  updateUser: (userId, changes) => request(`/admin/users/${id(userId)}`, { method: 'PATCH', body: changes }),
  resetPassword: (userId) => request(`/admin/users/${id(userId)}/reset-password`, { method: 'POST' }),
  searchAudit: ({ actor = '', action = '', limit, offset = 0 } = {}) => request(`/admin/audit?${new URLSearchParams({
    actor, action, offset: String(offset), ...(limit ? { limit: String(limit) } : {}),
  })}`),
  verifyAudit: () => request('/admin/audit/verify'),
  exportAudit: () => download('/admin/audit/export', 'journal-audit.json'),
  getSettings: () => request('/admin/settings'),
  saveSettings: (settings) => request('/admin/settings', { method: 'PUT', body: settings }),
  /** Message de test vers l'adresse de l'administrateur connecté, avec les réglages enregistrés. */
  testEmail: () => request('/admin/settings/email/test', { method: 'POST' }),
  getStorage: () => request('/admin/storage'),
  purgeStorage: () => request('/admin/storage/purge', { method: 'POST' }),
  cleanWorkspaces: () => request('/admin/storage/clean-workspaces', { method: 'POST' }),
};
