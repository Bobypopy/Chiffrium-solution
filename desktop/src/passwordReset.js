// Récupération de l'accès administrateur en mode local : le moteur est relancé une fois en ligne de commande
// (reset-password --sole-admin) avec la clé maîtresse que seule la session de l'utilisateur sait déchiffrer.
// La sortie de cette commande contient le mot de passe provisoire : elle n'est jamais écrite dans le journal.

const { spawn } = require('node:child_process');
const fs = require('node:fs');

const { backendEnvironment, resourcePaths } = require('./backend');

const RESET_TIMEOUT_MS = 120_000;

/** Dernière ligne JSON de la sortie : {"username": ..., "temporaryPassword": ...}, ou null. */
function parseResetOutput(output) {
  const lines = output.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.startsWith('{'));
  for (const line of lines.reverse()) {
    try {
      const value = JSON.parse(line);
      if (typeof value.username === 'string' && typeof value.temporaryPassword === 'string') return value;
    } catch {
      // ligne de journal qui commence par une accolade : ignorée
    }
  }
  return null;
}

/** Message de la commande en cas d'échec, sans rien qui ressemble à un mot de passe (sortie déjà en échec). */
function failureMessage(output) {
  const lines = output.split(/\r?\n/).map((line) => line.trim())
    .filter((line) => line && !line.startsWith('{') && !/^\d{2}:\d{2}|^\d{4}-\d{2}-\d{2}/.test(line));
  return lines.at(-1) ?? 'la commande de réinitialisation a échoué';
}

/**
 * @returns {Promise<{ username: string, temporaryPassword: string }>}
 */
function resetSoleAdminPassword({ resourcesDir, dataDir, masterKey, log }) {
  const paths = resourcePaths(resourcesDir);
  for (const required of [paths.java, paths.jar]) {
    if (!fs.existsSync(required)) return Promise.reject(new Error(`Ressource manquante : ${required}`));
  }
  return new Promise((resolve, reject) => {
    const env = backendEnvironment({ port: 0, dataDir, frontendDir: paths.frontend, masterKey, cdxgenCommand: null });
    delete env.EXIT_ON_STDIN_CLOSE;
    const child = spawn(paths.java, ['-jar', paths.jar, 'reset-password', '--sole-admin', '--yes', '--json'],
      { env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk.toString(); });
    child.stderr.on('data', (chunk) => { output += chunk.toString(); });
    const timer = setTimeout(() => child.kill(), RESET_TIMEOUT_MS);
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      const result = code === 0 ? parseResetOutput(output) : null;
      // Le journal ne garde que l'issue : la sortie peut contenir le mot de passe provisoire.
      log(`Réinitialisation du mot de passe administrateur : code ${code}${result ? ` (compte ${result.username})` : ''}.`);
      if (result) resolve(result);
      else reject(new Error(failureMessage(output)));
    });
  });
}

module.exports = { resetSoleAdminPassword, parseResetOutput, failureMessage };
