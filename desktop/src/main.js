// Processus principal de l'application de bureau. Deux modes (choisis au premier lancement) :
//   local  : démarre le backend embarqué sur 127.0.0.1 ;
//   server : client d'un serveur d'équipe (https).
// Gère aussi la fenêtre sécurisée, le menu, les mises à jour automatiques et l'arrêt propre.

const fs = require('node:fs');
const path = require('node:path');
const {
  app, BrowserWindow, Menu, dialog, ipcMain, safeStorage, session, shell,
} = require('electron');
const { startBackend } = require('./backend');
const { prepareCdxgenLauncher } = require('./cdxgen');
const {
  DATA_DIR_NAME, HEALTH_PATH, LOG_FILE_NAME, SERVER_CHECK_TIMEOUT_MS, UPDATE_CHECK_INTERVAL_MS, WINDOW,
} = require('./config');
const desktopConfig = require('./desktopConfig');
const { loadOrCreateMasterKey } = require('./masterKey');
const { CONTENT_SECURITY_POLICY, isAllowedNavigation, isExternalLink, isTrustedSender } = require('./security');
const { createUpdateController, STATUS } = require('./updater');

const ICON = path.join(__dirname, 'icon.png');
let backend = null;
/** Horodatages des redémarrages automatiques récents du moteur local. */
let backendRestarts = [];
const MAX_BACKEND_RESTARTS = 3;
const RESTART_WINDOW_MS = 5 * 60 * 1000;
let mainWindow = null;
let mode = null;
let quitting = false;
/** Fermeture déjà confirmée (analyses en cours) : ne pas redemander. */
let closeConfirmed = false;
/** Origine de l'interface chargée : seule page (avec l'écran d'accueil local) autorisée à appeler le pont. */
let appOrigin = null;
let updates = null;

const userDir = () => app.getPath('userData');
const dataDir = () => path.join(userDir(), DATA_DIR_NAME);
const logFile = () => path.join(userDir(), LOG_FILE_NAME);

/** Au-delà, le journal est archivé (une génération : desktop.old.log) pour ne pas remplir le disque. */
const MAX_LOG_BYTES = 5 * 1024 * 1024;

/** Nom du produit avant la 1.0.0 : ses données vivent dans un dossier voisin, à reprendre une fois. */
const ANCIEN_PRODUIT = 'CryptoAnalyzer';
/**
 * Ce qui nous appartient dans le dossier utilisateur (le reste est le cache de Chromium, à ne pas déplacer).
 *
 * "Local State" fait exception : c'est un fichier de Chromium, mais il contient la clé avec laquelle le
 * système a chiffré master.key.enc. Sans lui, la clé maîtresse devient illisible et l'application ne démarre
 * plus du tout ("Error while decrypting the ciphertext"). Il n'est repris que lors de la reprise, c'est-à-dire
 * avant que la nouvelle installation n'ait écrit quoi que ce soit.
 */
const AFFAIRES = ['data', 'bin', 'desktop-config.json', 'desktop.log', 'desktop.old.log',
  'master.key.enc', '.updaterId', 'Local State'];

/**
 * Reprend les données de l'ancien nom du produit. Sans cela, une installation existante repart vide :
 * analyses, catalogue, comptes et clé maîtresse restent dans %APPDATA%\CryptoAnalyzer sans que rien ne le
 * dise. La clé chiffrée reste lisible : le chiffrement du système est lié à l'utilisateur, pas au produit.
 */
function reprendreDonneesAnciennes() {
  try {
    const cible = userDir();
    const ancien = path.join(path.dirname(cible), ANCIEN_PRODUIT);
    if (ancien === cible || !fs.existsSync(ancien) || fs.existsSync(path.join(cible, DATA_DIR_NAME))) return;
    fs.mkdirSync(cible, { recursive: true });
    const repris = [];
    for (const nom of AFFAIRES) {
      const source = path.join(ancien, nom);
      if (!fs.existsSync(source)) continue;
      const destination = path.join(cible, nom);
      // Chromium a pu écrire son "Local State" avant nous : le sien ne vaut rien, celui de l'ancienne
      // installation porte la clé de déchiffrement.
      fs.rmSync(destination, { force: true, recursive: true });
      fs.renameSync(source, destination);
      repris.push(nom);
    }
    if (repris.length) log(`Données reprises depuis ${ANCIEN_PRODUIT} : ${repris.join(', ')}.`);
  } catch (error) {
    // Un échec ici ne doit pas empêcher l'application de démarrer : elle repartira sur un dossier vide.
    log(`Reprise des données de ${ANCIEN_PRODUIT} impossible : ${error.message}`);
  }
}

function rotateLog() {
  try {
    if (fs.statSync(logFile()).size > MAX_LOG_BYTES) {
      fs.renameSync(logFile(), logFile().replace(/\.log$/, '.old.log'));
    }
  } catch {
    // Pas encore de journal : rien à archiver.
  }
}

function log(message) {
  try {
    fs.appendFileSync(logFile(), message.endsWith('\n') ? message : `${message}\n`);
  } catch {
    // Journal indisponible : sans effet sur le fonctionnement.
  }
}

/** Ressources embarquées dans l'installateur, ou préparées dans desktop/resources en développement. */
function resourcesDir() {
  return app.isPackaged ? process.resourcesPath : path.join(__dirname, '..', 'resources');
}

function secureWebPreferences() {
  return {
    preload: path.join(__dirname, 'preload.js'),
    contextIsolation: true,
    nodeIntegration: false,
    sandbox: true,
    webSecurity: true,
    spellcheck: false,
  };
}

function hardenSession(appOrigin) {
  // Seule permission accordée : écrire dans le presse-papiers (boutons "Copier") depuis l'interface. La
  // lecture du presse-papiers, la caméra, les notifications système, etc. restent refusées.
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) =>
    callback(permission === 'clipboard-sanitized-write' && webContents.getURL().startsWith(appOrigin)));
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const headers = { ...details.responseHeaders };
    if (details.url.startsWith(appOrigin)) headers['Content-Security-Policy'] = [CONTENT_SECURITY_POLICY];
    callback({ responseHeaders: headers });
  });
}

function openWindow(loader) {
  mainWindow = new BrowserWindow({
    ...WINDOW, show: false, title: 'Chiffrium', icon: ICON, webPreferences: secureWebPreferences(),
  });
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isExternalLink(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.once('ready-to-show', () => mainWindow.show());
  mainWindow.on('close', confirmClose);
  loader(mainWindow);
}

/** Activité du moteur local (null en mode serveur d'équipe ou moteur arrêté). */
async function localActivity() {
  if (mode !== desktopConfig.MODES.LOCAL || !backend) return null;
  return backend.activity();
}

/**
 * Fermeture avec des analyses en cours : elles ne sont pas perdues (remises en file, reprises au prochain
 * lancement), mais l'utilisateur doit le savoir et pouvoir renoncer.
 */
function confirmClose(event) {
  if (quitting || closeConfirmed) return;
  event.preventDefault();
  requestQuit();
}

let confirming = false;

/** Fermeture (croix de la fenêtre ou Fichier > Quitter), confirmée si des analyses tournent. */
async function requestQuit() {
  if (confirming) return;
  confirming = true;
  try {
    const activity = await localActivity().catch(() => null);
    const busy = activity && (activity.running > 0 || activity.queued > 0);
    if (busy) {
      const { response } = await dialog.showMessageBox(mainWindow, {
        type: 'question',
        buttons: ['Quitter', 'Annuler'],
        defaultId: 1,
        cancelId: 1,
        title: 'Analyses en cours',
        message: `${activity.running} analyse(s) en cours et ${activity.queued} en attente.`,
        detail: 'Elles seront interrompues puis reprendront automatiquement depuis le début au prochain lancement '
          + 'de Chiffrium.',
      });
      if (response !== 0) return;
    }
    closeConfirmed = true;
    app.quit();
  } finally {
    confirming = false;
  }
}

function showApplication(appUrl) {
  appOrigin = new URL(appUrl).origin;
  hardenSession(appOrigin);
  const load = (window) => {
    window.webContents.removeAllListeners('will-navigate');
    window.webContents.on('will-navigate', (event, url) => {
      if (!isAllowedNavigation(url, appOrigin)) event.preventDefault();
    });
    window.loadURL(`${appOrigin}/`);
  };
  if (mainWindow) load(mainWindow);
  else openWindow(load);
}

function showWelcome() {
  openWindow((window) => {
    // Page locale : aucune navigation vers l'extérieur.
    window.webContents.on('will-navigate', (event) => event.preventDefault());
    window.loadFile(path.join(__dirname, 'welcome.html'));
  });
}

/** Vérifie qu'un serveur d'équipe répond avant de s'y connecter. */
async function checkServer(serverUrl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SERVER_CHECK_TIMEOUT_MS);
  try {
    const response = await fetch(`${serverUrl}${HEALTH_PATH}`, { signal: controller.signal });
    if (!response.ok) throw new Error(`réponse HTTP ${response.status}`);
  } finally {
    clearTimeout(timer);
  }
}

async function launchLocal(preferredPort = null) {
  const masterKey = loadOrCreateMasterKey(safeStorage, userDir());
  const cdxgenCommand = prepareCdxgenLauncher(path.join(userDir(), 'bin'), path.join(resourcesDir(), 'jre'));
  if (!cdxgenCommand) log('cdxgen non embarqué : analyses sans SBOM.');
  const started = await startBackend({ resourcesDir: resourcesDir(), dataDir: dataDir(), masterKey, cdxgenCommand, log,
    preferredPort, onExit: (code) => backendStopped(code, started.port) });
  backend = started;
  showApplication(backend.url);
}

/**
 * Le moteur local s'est arrêté sans qu'on le lui demande (plantage, processus tué) : on le relance sur le même
 * port, et la page se recharge. Les analyses interrompues reprennent au démarrage du moteur. Au-delà de
 * MAX_BACKEND_RESTARTS arrêts en RESTART_WINDOW_MS, on demande à l'utilisateur plutôt que de boucler.
 */
async function backendStopped(code, port) {
  if (quitting) return;
  backend = null;
  log(`Moteur d'analyse arrêté de façon inattendue (code ${code}).`);
  const now = Date.now();
  backendRestarts = backendRestarts.filter((time) => now - time < RESTART_WINDOW_MS);
  if (backendRestarts.length < MAX_BACKEND_RESTARTS) {
    backendRestarts.push(now);
    try {
      await launchLocal(port);
      return;
    } catch (error) {
      log(`Redémarrage du moteur impossible : ${error.stack ?? error.message}`);
    }
  }
  const { response } = await dialog.showMessageBox(mainWindow, {
    type: 'error',
    title: 'Moteur d\'analyse arrêté',
    message: 'Le moteur d\'analyse local s\'est arrêté.',
    detail: `Les analyses en cours reprendront au redémarrage.\n\nJournal : ${logFile()}`,
    buttons: ['Redémarrer', 'Quitter'],
    defaultId: 0,
  });
  if (response !== 0) {
    app.quit();
    return;
  }
  backendRestarts = [];
  try {
    await launchLocal(port);
  } catch (error) {
    log(`Redémarrage du moteur impossible : ${error.stack ?? error.message}`);
    dialog.showErrorBox('Moteur d\'analyse arrêté', `${error.message}\n\nJournal : ${logFile()}`);
  }
}

async function launch(config) {
  mode = config.mode;
  try {
    if (config.mode === desktopConfig.MODES.SERVER) {
      await checkServer(config.serverUrl);
      showApplication(config.serverUrl);
    } else {
      await launchLocal();
    }
  } catch (error) {
    log(`Démarrage impossible : ${error.stack ?? error.message}`);
    const { response } = await dialog.showMessageBox({
      type: 'error',
      title: 'Chiffrium ne peut pas démarrer',
      message: config.mode === desktopConfig.MODES.SERVER
        ? `Serveur d'équipe injoignable (${config.serverUrl}).` : 'Le moteur d\'analyse local ne démarre pas.',
      detail: `${error.message}\n\nJournal : ${logFile()}`,
      buttons: ['Réessayer', 'Changer de mode', 'Quitter'],
      defaultId: 0,
    });
    if (response === 0) return launch(config);
    if (response === 1) return changeMode();
    app.exit(1);
  }
  return undefined;
}

/** Revient à l'écran d'accueil (redémarrage : le backend local éventuel est arrêté proprement). */
function changeMode() {
  desktopConfig.reset(userDir());
  quitting = true;
  return stopBackend().finally(() => {
    app.relaunch();
    app.exit(0);
  });
}

/**
 * Pont réservé à l'interface de l'application (et à l'écran d'accueil local) : une page tierce affichée dans la
 * fenêtre, comme celle du fournisseur d'identité pendant une connexion SSO, n'y a pas accès.
 */
function handle(channel, handler) {
  ipcMain.handle(channel, (event, ...args) => {
    if (!isTrustedSender(event.senderFrame?.url, appOrigin)) {
      log(`Appel refusé sur ${channel} depuis ${event.senderFrame?.url}`);
      throw new Error('Appel non autorisé.');
    }
    return handler(event, ...args);
  });
}

function registerIpc() {
  // Jeton d'installation : proposé automatiquement à l'écran de première installation (mode local uniquement).
  handle('desktop:setup-token', () => {
    if (mode !== desktopConfig.MODES.LOCAL) return null;
    const file = path.join(dataDir(), 'secrets', 'setup-token');
    return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim() : null;
  });
  handle('desktop:version', () => app.getVersion());
  handle('desktop:mode', () => mode);
  handle('desktop:change-mode', () => changeMode());
  handle('desktop:update-state', () => updates.state());
  handle('desktop:update-check', () => updates.check());
  handle('desktop:update-activity', () => updates.activity());
  handle('desktop:update-install', (_event, when) => updates.install(when === 'when-idle' ? 'when-idle' : 'now'));
  handle('desktop:update-cancel', () => updates.cancelScheduled());
  handle('desktop:choose-mode', async (_event, choice) => {
    try {
      const config = desktopConfig.write(userDir(), choice ?? {});
      if (config.mode === desktopConfig.MODES.SERVER) await checkServer(config.serverUrl);
      launch(config);
      return { ok: true };
    } catch (error) {
      desktopConfig.reset(userDir());
      return { error: error.name === 'AbortError' ? 'Le serveur ne répond pas.' : error.message };
    }
  });
}

function buildMenu() {
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    {
      label: 'Fichier',
      submenu: [
        { label: 'Changer de mode (local / serveur d\'équipe)...', click: () => changeMode() },
        { type: 'separator' },
        { role: 'quit', label: 'Quitter' },
      ],
    },
    {
      label: 'Affichage',
      submenu: [
        { role: 'reload', label: 'Recharger' },
        { role: 'resetZoom', label: 'Taille normale' },
        { role: 'zoomIn', label: 'Agrandir' },
        { role: 'zoomOut', label: 'Réduire' },
        { role: 'togglefullscreen', label: 'Plein écran' },
      ],
    },
    {
      label: 'Aide',
      submenu: [
        {
          label: 'Guide d\'utilisation',
          accelerator: 'F1',
          click: () => mainWindow?.webContents.executeJavaScript("location.hash = '#/help'"),
        },
        { label: 'Ouvrir le dossier des données', click: () => shell.openPath(userDir()) },
        { label: 'Rechercher des mises à jour...', click: () => checkForUpdatesFromMenu() },
        { type: 'separator' },
        {
          label: 'À propos, licences et confidentialité',
          click: () => mainWindow?.webContents.executeJavaScript("location.hash = '#/about'"),
        },
        { label: 'Ouvrir le journal de l\'application', click: () => shell.openPath(logFile()) },
      ],
    },
  ]));
}

function setupAutoUpdate() {
  // Sans métadonnées de publication (construction locale), aucune source de mise à jour n'est configurée.
  const available = app.isPackaged && fs.existsSync(path.join(process.resourcesPath, 'app-update.yml'));
  let autoUpdater;
  if (available) {
    // Chargé seulement dans l'application installée (le module interroge l'application dès son import).
    ({ autoUpdater } = require('electron-updater'));
    autoUpdater.logger = { info: log, warn: log, error: log, debug: () => {} };
  }
  updates = createUpdateController({
    autoUpdater,
    activity: localActivity,
    beforeInstall: async () => {
      // Les analyses en cours sont remises en file par le moteur et reprendront après le redémarrage.
      quitting = true;
      closeConfirmed = true;
      await stopBackend();
    },
    onChange: (state) => {
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('desktop:update-changed', state);
    },
    log,
  });
  if (!available) return;
  updates.check();
  setInterval(() => updates.check(), UPDATE_CHECK_INTERVAL_MS).unref();
}

/** Aide > Rechercher des mises à jour : retour explicite (contrairement à la vérification silencieuse). */
async function checkForUpdatesFromMenu() {
  const state = await updates.check();
  const messages = {
    [STATUS.DISABLED]: ['Mises à jour automatiques indisponibles',
      'Cette copie a été construite localement : installez une version publiée pour recevoir les mises à jour.'],
    [STATUS.UP_TO_DATE]: ['Chiffrium est à jour', `Version installée : ${app.getVersion()}.`],
    [STATUS.DOWNLOADING]: [`Téléchargement de la version ${state.version}...`,
      'Un bouton "Mettre à jour" apparaîtra en haut de la fenêtre dès qu\'elle sera prête.'],
    [STATUS.READY]: [`La version ${state.version} est prête`, 'Cliquez sur "Mettre à jour" en haut de la fenêtre.'],
    [STATUS.ERROR]: ['Vérification impossible', `${state.error}\n\nVérifiez la connexion à Internet.`],
  };
  const [message, detail] = messages[state.status] ?? ['Vérification en cours...', ''];
  dialog.showMessageBox(mainWindow, { type: state.status === STATUS.ERROR ? 'warning' : 'info', title: 'Mises à jour',
    message, detail });
}

async function stopBackend() {
  if (backend) {
    const running = backend;
    backend = null;
    await running.stop();
  }
}

async function start() {
  rotateLog();
  buildMenu();
  setupAutoUpdate();
  registerIpc();
  const config = desktopConfig.read(userDir());
  if (config) await launch(config);
  else showWelcome();
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
  // Avant que Chromium ne s'installe dans le dossier utilisateur : il y écrit son "Local State", qu'il ne
  // faut surtout pas laisser prendre la place de celui qui porte la clé de déchiffrement.
  reprendreDonneesAnciennes();
  app.whenReady().then(start);
  app.on('window-all-closed', () => app.quit());
  app.on('before-quit', (event) => {
    if (quitting) return;
    if (!closeConfirmed) {
      // Fichier > Quitter passe ici avant la fermeture de la fenêtre : même confirmation que la croix.
      event.preventDefault();
      requestQuit();
      return;
    }
    if (updates?.isReady()) {
      // Mise à jour téléchargée en attente : on l'installe en partant, avec la fenêtre de l'installateur.
      // (electron-updater le ferait en silencieux, ce qui n'installe rien ici : voir updater.js.)
      event.preventDefault();
      updates.install('now').catch((error) => {
        log(`Installation de la mise à jour impossible : ${error?.message ?? error}`);
        quitting = true;
        stopBackend().finally(() => app.quit());
      });
      return;
    }
    if (!backend) return;
    event.preventDefault();
    quitting = true;
    stopBackend().finally(() => app.quit());
  });
}
