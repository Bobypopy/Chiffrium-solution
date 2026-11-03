// Pont minimal et en lecture seule entre l'interface et le processus principal (contextIsolation) :
// aucune API Node.js n'est exposée à la page.

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('desktop', Object.freeze({
  /** Jeton de première installation (null une fois le premier administrateur créé). */
  setupToken: () => ipcRenderer.invoke('desktop:setup-token'),
  version: () => ipcRenderer.invoke('desktop:version'),
  /** Mode courant : "local" ou "server". */
  mode: () => ipcRenderer.invoke('desktop:mode'),
  /** Écran d'accueil : choix du mode ({ mode, serverUrl }). */
  chooseMode: (choice) => ipcRenderer.invoke('desktop:choose-mode', choice),
  /** Retour à l'écran d'accueil pour changer de mode. */
  changeMode: () => ipcRenderer.invoke('desktop:change-mode'),
  /** Mises à jour de l'application (bouton "Mettre à jour" de l'interface). */
  update: Object.freeze({
    state: () => ipcRenderer.invoke('desktop:update-state'),
    check: () => ipcRenderer.invoke('desktop:update-check'),
    /** Analyses du moteur local ({ running, queued }), null en mode serveur d'équipe. */
    activity: () => ipcRenderer.invoke('desktop:update-activity'),
    /** when : "now" (analyses remises en file, reprises après redémarrage) ou "when-idle". */
    install: (when) => ipcRenderer.invoke('desktop:update-install', when),
    cancelScheduled: () => ipcRenderer.invoke('desktop:update-cancel'),
    onChange: (listener) => {
      const handler = (_event, state) => listener(state);
      ipcRenderer.on('desktop:update-changed', handler);
      return () => ipcRenderer.removeListener('desktop:update-changed', handler);
    },
  }),
}));
