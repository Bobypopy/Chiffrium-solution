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
  const stored = readIfPresent(file);
  if (stored !== null) return safeStorage.decryptString(stored);
  // Première exécution après une installation "fichier" : on reprend la clé existante pour ne rien perdre.
  const legacy = path.join(directory, 'data', 'secrets', 'master.key');
  const legacyKey = readIfPresent(legacy, 'utf8');
  const key = legacyKey !== null ? legacyKey.trim() : crypto.randomBytes(MASTER_KEY_BYTES).toString('base64');
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(file, safeStorage.encryptString(key), { mode: 0o600 });
  if (legacyKey !== null) fs.rmSync(legacy, { force: true });
  return key;
}

/** Lecture directe plutôt que existsSync puis lecture : le fichier ne peut pas changer entre les deux. */
function readIfPresent(file, encoding) {
  try {
    return fs.readFileSync(file, encoding);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

module.exports = { loadOrCreateMasterKey };
