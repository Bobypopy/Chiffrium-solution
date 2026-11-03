// Cycle de vie du backend Java embarqué : port libre, démarrage, attente de disponibilité, arrêt propre.

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const {
  BACKEND_START_TIMEOUT_MS, BACKEND_STOP_GRACE_MS, HEALTH_PATH, HEALTH_POLL_INTERVAL_MS, LOOPBACK,
} = require('./config');
const { explainFailure, stopOrphan } = require('./orphan');

const PID_FILE = 'backend.pid';
/** Délai laissé au système pour libérer le verrou de fichier après l'arrêt forcé d'un orphelin. */
const ORPHAN_RELEASE_DELAY_MS = 1500;
/** Fin de sortie du moteur conservée pour expliquer un échec de démarrage. */
const OUTPUT_TAIL_CHARS = 8000;
const CONTROL_TOKEN_BYTES = 32;
const ACTIVITY_PATH = '/api/desktop/activity';
/**
 * Sortie du moteur en UTF-8 : vers un tube, Java écrit System.out/err dans l'encodage du système (Cp1252 sous
 * Windows), et les accents des messages d'erreur montrés à l'utilisateur arriveraient illisibles.
 */
const JAVA_OUTPUT_OPTIONS = ['-Dstdout.encoding=UTF-8', '-Dstderr.encoding=UTF-8'];

/** Port TCP libre sur l'interface locale. */
function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, LOOPBACK, () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/** Vrai si `port` est libre sur l'interface locale. */
function portAvailable(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.unref();
    server.once('error', () => resolve(false));
    server.listen(port, LOOPBACK, () => server.close(() => resolve(true)));
  });
}

/** Chemins des ressources embarquées (installateur) ou du dépôt (développement). */
function resourcePaths(resourcesDir) {
  const javaBinary = process.platform === 'win32' ? 'java.exe' : 'java';
  return {
    java: path.join(resourcesDir, 'jre', 'bin', javaBinary),
    jar: path.join(resourcesDir, 'backend', 'chiffrium-backend.jar'),
    frontend: path.join(resourcesDir, 'frontend'),
  };
}

/**
 * Variables d'environnement du backend (voir AppConfig côté Java).
 * Les dossiers de l'utilisateur sont analysables : c'est l'usage principal de l'application de bureau.
 */
function backendEnvironment({ port, dataDir, frontendDir, masterKey, cdxgenCommand, controlToken }) {
  const env = {
    ...process.env,
    PORT: String(port),
    BIND_ADDRESS: LOOPBACK,
    DATA_DIR: dataDir,
    STATIC_DIR: frontendDir,
    ALLOWED_LOCAL_ROOTS: os.homedir(),
    EXIT_ON_STDIN_CLOSE: 'true',
    TRUST_PROXY: 'false',
  };
  if (masterKey) env.MASTER_KEY = masterKey;
  if (cdxgenCommand) env.CDXGEN_COMMAND = cdxgenCommand;
  // Canal privé (activité des analyses) : jeton aléatoire connu du seul processus principal.
  if (controlToken) env.DESKTOP_CONTROL_TOKEN = controlToken;
  delete env.ELECTRON_RUN_AS_NODE;
  return env;
}

async function waitForHealth(baseUrl, child, output, timeoutMs = BACKEND_START_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(explainFailure(output()) ?? `Le moteur d'analyse s'est arrêté (code ${child.exitCode}).`);
    }
    try {
      const response = await fetch(`${baseUrl}${HEALTH_PATH}`);
      if (response.ok) return;
    } catch {
      // Pas encore à l'écoute.
    }
    await new Promise((resolve) => setTimeout(resolve, HEALTH_POLL_INTERVAL_MS));
  }
  throw new Error('Le backend ne répond pas dans le délai imparti.');
}

/**
 * Démarre le backend et attend qu'il réponde.
 * @param {number} [preferredPort] port à réutiliser s'il est libre (redémarrage : même origine, la session de
 *   l'interface est conservée)
 * @param {(code: number | null) => void} [onExit] appelé si le moteur s'arrête sans qu'on le lui ait demandé
 * @returns {Promise<{ url: string, port: number, stop: () => Promise<void>,
 *   activity: () => Promise<{ running: number, queued: number }> }>}
 */
async function startBackend({ resourcesDir, dataDir, masterKey, cdxgenCommand, log, preferredPort = null, onExit = null }) {
  const paths = resourcePaths(resourcesDir);
  for (const required of [paths.java, paths.jar]) {
    if (!fs.existsSync(required)) throw new Error(`Ressource manquante : ${required}`);
  }
  const pidFile = path.join(dataDir, PID_FILE);
  if (stopOrphan(pidFile, paths.jar, log)) {
    await new Promise((resolve) => setTimeout(resolve, ORPHAN_RELEASE_DELAY_MS));
  }
  const port = preferredPort && await portAvailable(preferredPort) ? preferredPort : await freePort();
  const url = `http://${LOOPBACK}:${port}`;
  const controlToken = crypto.randomBytes(CONTROL_TOKEN_BYTES).toString('hex');
  fs.mkdirSync(dataDir, { recursive: true });
  const child = spawn(paths.java, [...JAVA_OUTPUT_OPTIONS, '-jar', paths.jar], {
    env: backendEnvironment({ port, dataDir, frontendDir: paths.frontend, masterKey, cdxgenCommand, controlToken }),
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
  fs.writeFileSync(pidFile, String(child.pid));
  child.once('exit', () => fs.rmSync(pidFile, { force: true }));
  let tail = '';
  const record = (text) => {
    log(text);
    tail = (tail + text).slice(-OUTPUT_TAIL_CHARS);
  };
  // Décodage par flux : un caractère accentué coupé entre deux morceaux n'est pas abîmé.
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', record);
  child.stderr.on('data', record);
  await waitForHealth(url, child, () => tail);
  let stopping = false;
  child.once('exit', (code) => {
    if (!stopping) onExit?.(code);
  });

  const stop = () => new Promise((resolve) => {
    stopping = true;
    if (child.exitCode !== null) {
      resolve();
      return;
    }
    const timer = setTimeout(() => child.kill(), BACKEND_STOP_GRACE_MS);
    child.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
    // Fermer l'entrée standard déclenche l'arrêt propre du backend (EXIT_ON_STDIN_CLOSE).
    child.stdin.end();
  });
  const activity = async () => {
    const response = await fetch(`${url}${ACTIVITY_PATH}`, { headers: { 'X-Desktop-Token': controlToken } });
    if (!response.ok) throw new Error(`activité indisponible (HTTP ${response.status})`);
    return response.json();
  };
  return { url, port, stop, activity };
}

module.exports = { startBackend, backendEnvironment, resourcePaths, freePort, JAVA_OUTPUT_OPTIONS };
