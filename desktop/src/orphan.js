// Moteur local orphelin : si l'application a été arrêtée brutalement pendant que le moteur finissait ses
// analyses, celui-ci peut encore tenir le verrou de la base au relancement. On l'identifie par son fichier PID
// et par sa ligne de commande (jamais un autre processus Java de l'utilisateur), puis on l'arrête.

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');

const WINDOWS = process.platform === 'win32';
const POWERSHELL = 'powershell.exe';

function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Ligne de commande d'un processus (chaîne vide si introuvable). */
function commandLine(pid) {
  try {
    if (WINDOWS) {
      return execFileSync(POWERSHELL, ['-NoProfile', '-Command',
        `(Get-CimInstance Win32_Process -Filter "ProcessId=${Number(pid)}").CommandLine`],
      { encoding: 'utf8', windowsHide: true }).trim();
    }
    return fs.readFileSync(`/proc/${Number(pid)}/cmdline`, 'utf8').replaceAll('\0', ' ');
  } catch {
    return '';
  }
}

/**
 * Arrête le moteur d'une session précédente s'il tourne encore.
 * @param {string} pidFile fichier PID écrit au démarrage du moteur
 * @param {string} jarPath jar du moteur (signature de la ligne de commande)
 * @returns {boolean} vrai si un orphelin a été arrêté
 */
function stopOrphan(pidFile, jarPath, log) {
  let pid;
  try {
    pid = Number.parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
  } catch {
    return false;
  }
  fs.rmSync(pidFile, { force: true });
  if (!Number.isInteger(pid) || pid <= 0 || !isAlive(pid) || !commandLine(pid).includes(jarPath)) {
    return false;
  }
  log(`Moteur orphelin détecté (PID ${pid}) : arrêt.`);
  try {
    if (WINDOWS) execFileSync('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true });
    else process.kill(pid, 'SIGKILL');
  } catch (error) {
    log(`Arrêt du moteur orphelin impossible : ${error.message}`);
  }
  return true;
}

/** Message compréhensible à partir de la fin du journal du moteur. */
function explainFailure(output) {
  if (/file is locked|en cours d'utilisation|already in use/i.test(output)) {
    return 'La base locale est déjà utilisée par une autre instance de Chiffrium. Fermez-la puis réessayez.';
  }
  if (/clé maîtresse incorrecte|AEADBadTag|Wrong user name or password/i.test(output)) {
    return 'La base locale ne peut pas être déchiffrée avec la clé de ce profil (clé maîtresse différente).';
  }
  return null;
}

module.exports = { stopOrphan, explainFailure, isAlive };
