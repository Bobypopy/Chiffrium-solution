// Constantes de l'application de bureau (aucun nombre magique dans le reste du code).

module.exports = Object.freeze({
  /** Interface d'écoute du backend : jamais exposé sur le réseau. */
  LOOPBACK: '127.0.0.1',
  /** Attente maximale du démarrage du backend (JVM + migrations de la base). */
  BACKEND_START_TIMEOUT_MS: 90_000,
  HEALTH_POLL_INTERVAL_MS: 300,
  /** Délai de réponse attendu d'un serveur d'équipe avant de s'y connecter. */
  SERVER_CHECK_TIMEOUT_MS: 10_000,
  /** Délai laissé au backend pour terminer proprement après fermeture de son entrée standard. */
  BACKEND_STOP_GRACE_MS: 15_000,
  /** Vérification périodique des mises à jour. */
  UPDATE_CHECK_INTERVAL_MS: 6 * 60 * 60 * 1000,
  WINDOW: Object.freeze({ width: 1400, height: 900, minWidth: 960, minHeight: 640 }),
  HEALTH_PATH: '/api/health',
  MASTER_KEY_FILE: 'master.key.enc',
  MASTER_KEY_BYTES: 32,
  DATA_DIR_NAME: 'data',
  LOG_FILE_NAME: 'desktop.log',
});
