// Écran d'accueil (page locale, sans accès Node) : transmet le choix au processus principal.

const error = document.getElementById('error');

document.getElementById('local').addEventListener('click', () => {
  // Le moteur met jusqu'à une minute à démarrer la première fois, sans rien d'autre à l'écran : un second
  // clic relançait un moteur qui arrêtait le premier. Les boutons restent désactivés jusqu'à ce que
  // l'application remplace cette page (en cas d'échec, la boîte d'erreur propose de réessayer ou de changer de mode).
  for (const button of document.querySelectorAll('button')) button.disabled = true;
  document.getElementById('local-status').textContent =
    'Démarrage du moteur d\'analyse... (jusqu\'à une minute au premier lancement)';
  window.desktop.chooseMode({ mode: 'local' });
});

document.getElementById('server-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  error.textContent = '';
  const button = event.submitter;
  button.disabled = true;
  try {
    const result = await window.desktop.chooseMode({
      mode: 'server', serverUrl: document.getElementById('server-url').value,
    });
    if (result?.error) error.textContent = result.error;
  } finally {
    button.disabled = false;
  }
});
