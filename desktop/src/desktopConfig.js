// Mode de fonctionnement de l'application de bureau, choisi au premier lancement :
//   local  : backend embarqué, données sur ce poste ;
//   server : client d'un serveur d'équipe (comptes, groupes, analyses partagés).

const fs = require('node:fs');
const path = require('node:path');

const CONFIG_FILE = 'desktop-config.json';
const MODES = Object.freeze({ LOCAL: 'local', SERVER: 'server' });
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Valide l'adresse d'un serveur d'équipe : https obligatoire (sauf poste local pour les essais), sans
 * identifiants ni fragment ; renvoie l'origine normalisée.
 * @throws {Error} message destiné à l'utilisateur
 */
function normalizeServerUrl(value) {
  let url;
  try {
    url = new URL(String(value ?? '').trim());
  } catch {
    throw new Error('Adresse invalide (exemple : https://chiffrium.mon-entreprise.fr).');
  }
  const loopback = LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error('Le serveur doit être en https (les échanges contiennent des identifiants et des rapports).');
  }
  if (url.username || url.password) {
    throw new Error('L\'adresse ne doit pas contenir d\'identifiants.');
  }
  return url.origin;
}

function read(directory) {
  try {
    const config = JSON.parse(fs.readFileSync(path.join(directory, CONFIG_FILE), 'utf8'));
    if (config.mode === MODES.LOCAL) return { mode: MODES.LOCAL };
    if (config.mode === MODES.SERVER) return { mode: MODES.SERVER, serverUrl: normalizeServerUrl(config.serverUrl) };
  } catch {
    // Absent ou invalide : l'écran d'accueil propose à nouveau le choix.
  }
  return null;
}

function write(directory, config) {
  const clean = config.mode === MODES.SERVER
    ? { mode: MODES.SERVER, serverUrl: normalizeServerUrl(config.serverUrl) }
    : { mode: MODES.LOCAL };
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, CONFIG_FILE), JSON.stringify(clean, null, 2), { mode: 0o600 });
  return clean;
}

function reset(directory) {
  fs.rmSync(path.join(directory, CONFIG_FILE), { force: true });
}

module.exports = { MODES, normalizeServerUrl, read, write, reset };
