// Clé maîtresse protégée par le trousseau du système (DPAPI sous Windows, libsecret/kwallet sous Linux) via
// safeStorage : elle n'est jamais écrite en clair et n'est lisible que par la session de l'utilisateur.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { MASTER_KEY_BYTES, MASTER_KEY_FILE } = require('./config');

/**
 * @returns {string|null} clé en Base64 à transmettre au backend (variable MASTER_KEY), ou null si le trousseau
 * est indisponible : le backend utilise alors son fichier data/secrets/master.key à droits restreints.
 */
function loadOrCreateMasterKey(safeStorage, directory) {
  if (!safeStorage.isEncryptionAvailable()) return null;
  const file = path.join(directory, MASTER_KEY_FILE);
  if (fs.existsSync(file)) {
    return safeStorage.decryptString(fs.readFileSync(file));
  }
  // Première exécution après une installation "fichier" : on reprend la clé existante pour ne rien perdre.
  const legacy = path.join(directory, 'data', 'secrets', 'master.key');
  const key = fs.existsSync(legacy)
    ? fs.readFileSync(legacy, 'utf8').trim()
    : crypto.randomBytes(MASTER_KEY_BYTES).toString('base64');
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(file, safeStorage.encryptString(key), { mode: 0o600 });
  if (fs.existsSync(legacy)) fs.rmSync(legacy);
  return key;
}

module.exports = { loadOrCreateMasterKey };
