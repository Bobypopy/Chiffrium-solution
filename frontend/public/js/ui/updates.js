// Mises à jour vues de l'interface :
//  - application de bureau : bouton "Mettre à jour" (téléchargement, puis choix du moment selon les analyses) ;
//  - serveur mis à jour pendant que la page est ouverte : proposition de recharger (sinon ancien code + nouvelle API) ;
//  - premier affichage après une mise à jour : message de confirmation.

import { h, mount, toast } from './dom.js';

const SERVER_VERSION_POLL_MS = 5 * 60 * 1000;
const LAST_VERSION_KEY = 'chiffrium.lastVersion';

let loadedVersion = null;

async function serverVersion() {
  const response = await fetch('api/health', { cache: 'no-store' });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return (await response.json()).version ?? null;
}

function rememberVersion(version) {
  let previous = null;
  try {
    previous = localStorage.getItem(LAST_VERSION_KEY);
    localStorage.setItem(LAST_VERSION_KEY, version);
  } catch {
    // Stockage indisponible : pas de message "mis à jour", sans autre conséquence.
  }
  if (previous && previous !== version) {
    toast(`Chiffrium a été mis à jour : version ${previous} -> ${version}.`, 'good');
  }
}

/** Serveur mis à jour depuis le chargement de la page : bandeau "Recharger". */
function watchServerVersion(area) {
  const check = async () => {
    try {
      const version = await serverVersion();
      if (!version) return;
      if (!loadedVersion) {
        loadedVersion = version;
        rememberVersion(version);
      } else if (version !== loadedVersion) {
        mount(area, h('div', { class: 'update-pill', role: 'status' },
          `Version ${version} disponible`,
          h('button', { class: 'button small primary', type: 'button', onclick: () => location.reload() },
            'Recharger la page')));
      }
    } catch {
      // Serveur momentanément injoignable (redémarrage en cours) : nouvel essai au prochain passage.
    }
  };
  check();
  setInterval(check, SERVER_VERSION_POLL_MS);
  window.addEventListener('focus', check);
}

function plural(count, word) {
  return `${count} ${word}${count > 1 ? 's' : ''}`;
}

/** Fenêtre de choix : quand installer, selon les analyses en cours sur ce poste. */
async function openInstallDialog(bridge, state) {
  const activity = await bridge.activity().catch(() => null);
  const busy = activity && (activity.running > 0 || activity.queued > 0);
  const dialog = h('dialog', { class: 'modal', 'aria-labelledby': 'update-title' });
  const close = () => {
    dialog.close();
    dialog.remove();
  };
  const run = (when) => async () => {
    close();
    try {
      await bridge.install(when);
      if (when === 'when-idle' && busy) {
        toast('La mise à jour s\'installera automatiquement à la fin des analyses.', 'good');
      }
    } catch (error) {
      toast(error.message, 'critical');
    }
  };
  mount(dialog,
    h('h2', { id: 'update-title' }, `Mettre à jour vers la version ${state.version}`),
    busy
      ? [h('p', {}, h('strong', {}, `${plural(activity.running, 'analyse')} en cours`),
        activity.queued ? ` et ${plural(activity.queued, 'analyse')} en attente` : '', ' sur ce poste.'),
      h('ul', { class: 'modal-options' },
        h('li', {}, h('strong', {}, 'À la fin des analyses (recommandé) : '),
          'l\'application redémarre d\'elle-même dès que la file est vide. Vous pouvez continuer à travailler.'),
        h('li', {}, h('strong', {}, 'Maintenant : '), 'les analyses sont interrompues et reprendront automatiquement ',
          'depuis le début après le redémarrage (aucune n\'est perdue).'),
        h('li', {}, h('strong', {}, 'Plus tard : '), 'la mise à jour s\'installera à la fermeture de l\'application.'))]
      : h('p', {}, activity ? 'Aucune analyse en cours sur ce poste. ' : '',
        'L\'application va se fermer, installer la mise à jour et redémarrer (quelques secondes).'),
    h('p', { class: 'hint' }, 'Vos analyses, comptes et paramètres sont conservés. Enregistrez d\'abord une ',
      'modification en cours (catalogue, paramètres) : la page sera rechargée.'),
    h('div', { class: 'actions modal-actions' },
      busy ? h('button', { class: 'button primary', type: 'button', onclick: run('when-idle') },
        'À la fin des analyses') : null,
      h('button', { class: `button ${busy ? '' : 'primary'}`, type: 'button', onclick: run('now') },
        busy ? 'Maintenant' : 'Redémarrer et mettre à jour'),
      h('button', { class: 'button ghost', type: 'button', onclick: close }, 'Plus tard')));
  dialog.addEventListener('cancel', close);
  document.body.append(dialog);
  dialog.showModal();
}

/** Bouton de l'application de bureau, redessiné à chaque changement d'état. */
function renderDesktopUpdate(area, bridge, state) {
  if (state.installWhenIdle) {
    const waiting = state.waitingFor;
    mount(area, h('div', { class: 'update-pill', role: 'status' },
      `Mise à jour ${state.version} programmée`,
      waiting ? h('span', { class: 'muted small' }, ` - ${plural(waiting.running + waiting.queued, 'analyse')} restante(s)`)
        : null,
      h('button', { class: 'button small ghost', type: 'button',
        onclick: () => bridge.cancelScheduled().then(() => toast('Installation reportée à la fermeture.', 'neutral')) },
      'Annuler')));
    return;
  }
  switch (state.status) {
    case 'downloading':
      mount(area, h('span', { class: 'update-pill muted small', role: 'status',
        title: 'La mise à jour se télécharge en arrière-plan ; vous pouvez continuer à travailler.' },
      `Téléchargement de la mise à jour... ${state.percent ?? 0} %`));
      break;
    case 'ready':
      mount(area, h('button', {
        class: 'button small primary', type: 'button', title: 'Installer la nouvelle version',
        onclick: () => openInstallDialog(bridge, state),
      }, `Mettre à jour (v${state.version})`));
      break;
    default:
      mount(area);
  }
}

export async function setupUpdates() {
  const container = document.getElementById('update-area');
  if (!container) return;
  // Deux emplacements : l'un ne doit pas effacer l'autre (bureau en mode serveur).
  const area = h('div', { class: 'update-slot' });
  const serverArea = h('div', { class: 'update-slot' });
  container.append(area, serverArea);
  const bridge = window.desktop?.update;
  if (bridge) {
    bridge.onChange((state) => renderDesktopUpdate(area, bridge, state));
    renderDesktopUpdate(area, bridge, await bridge.state().catch(() => ({ status: 'disabled' })));
  }
  // Bureau en mode local : le moteur redémarre avec l'application, seule la confirmation de version sert.
  watchServerVersion(bridge && (await window.desktop.mode().catch(() => null)) === 'local'
    ? h('div') : serverArea);
}
