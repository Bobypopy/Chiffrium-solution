// Mises à jour de l'application : état observable par l'interface (bouton "Mettre à jour") et installation
// sans perdre de travail. Indépendant d'Electron pour être testé : electron-updater est injecté.

/** Vérification de l'inactivité pendant l'attente de la fin des analyses. */
const IDLE_POLL_MS = 10_000;

const STATUS = Object.freeze({
  DISABLED: 'disabled', // construction locale : aucune source de mise à jour
  IDLE: 'idle',
  CHECKING: 'checking',
  UP_TO_DATE: 'up-to-date',
  DOWNLOADING: 'downloading',
  READY: 'ready',
  ERROR: 'error',
});

/**
 * @param {object} options
 * @param {import('events').EventEmitter & {checkForUpdates: Function, quitAndInstall: Function}} [options.autoUpdater]
 *        absent : mises à jour désactivées
 * @param {() => Promise<{running: number, queued: number} | null>} options.activity analyses du moteur local
 *        (null en mode serveur d'équipe : rien ne s'exécute sur ce poste)
 * @param {() => Promise<void>} options.beforeInstall arrêt propre du moteur (les analyses en cours sont remises en file)
 * @param {(state: object) => void} options.onChange diffusion de l'état à l'interface
 * @param {(message: string) => void} [options.log]
 */
function createUpdateController({ autoUpdater, activity, beforeInstall, onChange, log = () => {},
  timers = { setInterval, clearInterval } }) {
  let state = { status: autoUpdater ? STATUS.IDLE : STATUS.DISABLED, version: null, percent: 0, error: null,
    installWhenIdle: false, waitingFor: null };
  let idleTimer = null;
  let installing = false;

  const set = (changes) => {
    state = { ...state, ...changes };
    onChange({ ...state });
  };

  const install = async () => {
    if (installing) return;
    installing = true;
    stopWaiting();
    log(`Installation de la mise à jour ${state.version}`);
    try {
      await beforeInstall();
    } finally {
      // Installateur visible : sa barre de progression montre que la mise à jour avance (en mode silencieux,
      // plus rien n'était affiché pendant une à deux minutes). Les questions (dossier, licence, type
      // d'installation) sont sautées pour une mise à jour : voir build/installer.nsh.
      autoUpdater.quitAndInstall(false, true);
    }
  };

  function stopWaiting() {
    if (idleTimer) timers.clearInterval(idleTimer);
    idleTimer = null;
  }

  const pollIdle = async () => {
    const current = await activity().catch(() => null);
    if (!current || (current.running === 0 && current.queued === 0)) {
      await install();
    } else {
      set({ waitingFor: current });
    }
  };

  if (autoUpdater) {
    autoUpdater.autoDownload = true;
    // "Plus tard" : la mise à jour s'installe à la fermeture, mais c'est nous qui la lançons (voir isReady()
    // et main.js), avec la fenêtre de l'installateur. Sa barre de progression montre que la mise à jour
    // avance, et un échec devient visible : en 2.5.0, une installation silencieuse échouait sans le moindre
    // message et la version cassée restait en place alors que son correctif était déjà téléchargé (la cause
    // de cet échec est corrigée en 2.5.3, voir desktop/build/installer.nsh).
    autoUpdater.autoInstallOnAppQuit = false;
    autoUpdater.on('checking-for-update', () => {
      if (state.status !== STATUS.READY && state.status !== STATUS.DOWNLOADING) set({ status: STATUS.CHECKING });
    });
    autoUpdater.on('update-not-available', () => set({ status: STATUS.UP_TO_DATE, error: null }));
    autoUpdater.on('update-available', (info) => set({ status: STATUS.DOWNLOADING, version: info.version, percent: 0 }));
    autoUpdater.on('download-progress', (progress) => set({ status: STATUS.DOWNLOADING,
      percent: Math.round(progress.percent ?? 0) }));
    autoUpdater.on('update-downloaded', (info) => set({ status: STATUS.READY, version: info.version, percent: 100 }));
    autoUpdater.on('error', (error) => {
      log(`Mise à jour : ${error?.message ?? error}`);
      // Une mise à jour déjà téléchargée reste installable malgré une vérification ultérieure en échec.
      if (state.status !== STATUS.READY) set({ status: STATUS.ERROR, error: error?.message ?? String(error) });
    });
  }

  return {
    state: () => ({ ...state }),

    /** Une mise à jour est téléchargée et attend : l'application l'installe alors en se fermant. */
    isReady: () => state.status === STATUS.READY && !installing,

    /** Recherche une mise à jour (téléchargée automatiquement si disponible). */
    async check() {
      if (!autoUpdater) return { ...state };
      try {
        await autoUpdater.checkForUpdates();
      } catch (error) {
        if (state.status !== STATUS.READY) set({ status: STATUS.ERROR, error: error.message });
      }
      return { ...state };
    },

    /** Activité locale au moment de décider (null en mode serveur). */
    activity: () => activity().catch(() => null),

    /**
     * @param {'now' | 'when-idle'} when "now" interrompt les analyses (remises en file, elles reprendront
     *        après le redémarrage) ; "when-idle" attend que la file soit vide.
     */
    async install(when = 'now') {
      if (state.status !== STATUS.READY) throw new Error('Aucune mise à jour prête à installer.');
      if (when === 'when-idle') {
        const current = await activity().catch(() => null);
        if (!current || (current.running === 0 && current.queued === 0)) return install();
        set({ installWhenIdle: true, waitingFor: current });
        stopWaiting();
        idleTimer = timers.setInterval(pollIdle, IDLE_POLL_MS);
        return undefined;
      }
      return install();
    },

    /** Renonce à l'installation automatique en fin d'analyses (elle se fera à la fermeture). */
    cancelScheduled() {
      stopWaiting();
      set({ installWhenIdle: false, waitingFor: null });
    },
  };
}

module.exports = { createUpdateController, STATUS, IDLE_POLL_MS };
