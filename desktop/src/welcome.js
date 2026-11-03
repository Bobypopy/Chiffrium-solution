// Écran d'accueil (page locale, sans accès Node) : transmet le choix au processus principal.

const error = document.getElementById('error');

document.getElementById('local').addEventListener('click', () => {
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
