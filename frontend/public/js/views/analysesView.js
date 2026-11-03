import { api } from '../api.js';
import { elapsed, formatDate, formatDuration, parseTargets, plural, shortTarget } from '../domain/format.js';
import { VIEWS, comparisonOrder, filterJobs, groupView, queuePositions } from '../domain/jobs.js';
import { JOB_STATUS_LABELS, JOB_STATUS_STYLES, isActiveJob } from '../domain/labels.js';
import { scoreTone } from '../domain/report.js';
import { PERMISSIONS, session } from '../session.js';
import { badge, emptyState, h, mount, toast } from '../ui/dom.js';

const POLL_INTERVAL_MS = 3000;
const COMPARE_SIZE = 2;
const VIEW_KEY = 'chiffrium.analysesView';

function storedView() {
  try {
    return sessionStorage.getItem(VIEW_KEY) || VIEWS.ALL;
  } catch {
    return VIEWS.ALL;
  }
}

/**
 * Vue d'accueil : lancement d'analyses, suivi, favoris, groupes et comparaison.
 * @returns {() => void} fonction de nettoyage (arrêt du rafraîchissement)
 */
export function renderAnalyses(container, { info }) {
  const list = h('div', { class: 'jobs', 'aria-live': 'polite' });
  const state = { view: storedView(), text: '', favorites: new Set(), groups: [], jobs: [], selected: new Set(),
    openMenu: null };
  const username = session.current()?.user?.username;
  const viewSelect = h('select', { 'aria-label': 'Afficher' });
  const compareBar = h('div', { class: 'compare-bar', hidden: true });
  let timer = null;
  let stopped = false;

  const groupName = (groupId) => state.groups.find((g) => g.groupId === groupId)?.groupName;

  const draw = () => {
    const jobs = filterJobs(state.jobs, { view: state.view, text: state.text, username, favorites: state.favorites });
    const positions = queuePositions(state.jobs);
    mount(list, jobs.length ? jobsTable(jobs, { state, groupName, refresh, draw, positions })
      : state.jobs.length ? emptyState('Aucune analyse ne correspond à ce filtre.')
        : h('div', { class: 'empty-guide' },
          h('p', {}, h('strong', {}, 'Aucune analyse pour le moment.')),
          session.can(PERMISSIONS.RUN_ANALYSIS)
            ? h('p', { class: 'muted' }, 'Collez l\'adresse d\'un dépôt Git dans "Nouvelle analyse", puis cliquez sur ',
              '"Lancer l\'analyse". Comptez de quelques secondes à plusieurs minutes selon ',
              'la taille du dépôt ; vous pouvez l\'arrêter à tout moment.')
            : h('p', { class: 'muted' }, 'Les analyses partagées avec vos groupes apparaîtront ici.')));
    const selected = state.jobs.filter((j) => state.selected.has(j.id));
    compareBar.hidden = selected.length === 0;
    mount(compareBar, selected.length === COMPARE_SIZE
      ? h('button', {
        class: 'button primary', type: 'button',
        onclick: () => {
          const [base, target] = comparisonOrder(selected[0], selected[1]);
          location.hash = `#/compare/${base.id}/${target.id}`;
        },
      }, 'Comparer les deux analyses sélectionnées')
      : h('span', { class: 'muted' }, 'Sélectionnez une deuxième analyse terminée pour comparer.'),
    h('button', { class: 'button ghost small', type: 'button',
      onclick: () => { state.selected.clear(); draw(); } }, 'Annuler'));
  };

  const drawViews = () => mount(viewSelect,
    [[VIEWS.ALL, 'Toutes les analyses visibles'], [VIEWS.MINE, 'Mes analyses'], [VIEWS.FAVORITES, 'Favoris'],
      ...state.groups.map((g) => [groupView(g.groupId), `Groupe : ${g.groupName}`])]
      .map(([value, text]) => h('option', { value, selected: state.view === value }, text)));

  async function refresh() {
    try {
      const [jobs, favorites] = await Promise.all([api.listAnalyses(), api.listFavorites()]);
      state.jobs = jobs;
      state.favorites = new Set(favorites);
      draw();
      const active = jobs.some(isActiveJob);
      if (!stopped && active) timer = setTimeout(refresh, POLL_INTERVAL_MS);
    } catch (error) {
      mount(list, emptyState(`Impossible de charger les analyses : ${error.message}`));
    }
  }

  viewSelect.addEventListener('change', (e) => {
    state.view = e.target.value;
    try {
      sessionStorage.setItem(VIEW_KEY, state.view);
    } catch {
      // Préférence non mémorisée.
    }
    draw();
  });

  const formHolder = h('div');
  mount(container,
    session.can(PERMISSIONS.RUN_ANALYSIS) ? h('section', { class: 'card' },
      h('h2', {}, 'Nouvelle analyse'), formHolder, capabilities(info))
      : h('p', { class: 'hint' }, 'Rôle lecteur : consultation des analyses de vos groupes.'),
    h('section', { class: 'card' },
      h('div', { class: 'card-header' },
        h('h2', {}, 'Analyses'),
        h('button', { class: 'button ghost', type: 'button', onclick: () => { clearTimeout(timer); refresh(); } },
          'Actualiser')),
      h('div', { class: 'filters' },
        viewSelect,
        h('input', {
          type: 'search', placeholder: 'Rechercher (dépôt, libellé, demandeur)...', 'aria-label': 'Rechercher une analyse',
          oninput: (e) => { state.text = e.target.value; draw(); },
        })),
      compareBar,
      list));

  api.myGroups().then((groups) => {
    state.groups = groups;
    if (state.view.startsWith('group:') && !groups.some((g) => groupView(g.groupId) === state.view)) {
      state.view = VIEWS.ALL;
    }
    drawViews();
    if (session.can(PERMISSIONS.RUN_ANALYSIS)) {
      mount(formHolder, analysisForm(info, groups, async (submission) => {
        const jobs = await api.submitAnalyses(submission);
        toast(`${plural(jobs.length, 'analyse lancée', 'analyses lancées')}.`, 'good');
        clearTimeout(timer);
        refresh();
      }));
    }
    draw();
  }).catch(() => drawViews());
  drawViews();
  refresh();
  return () => {
    stopped = true;
    clearTimeout(timer);
  };
}

function analysisForm(info, groups, onSubmit) {
  const targets = h('textarea', {
    id: 'targets', rows: 4, required: true, spellcheck: 'false',
    placeholder: 'https://gitlab.com/groupe/projet.git\nhttps://github.com/organisation/depot.git\n(une cible par ligne)',
  });
  const branch = h('input', { id: 'branch', type: 'text', placeholder: 'branche par défaut' });
  const timeout = h('input', {
    id: 'timeout', type: 'number', min: 30, max: info?.cdxgenMaxTimeoutSeconds ?? 7200,
    placeholder: String(info?.cdxgenDefaultTimeoutSeconds ?? 900),
  });
  const group = h('select', { id: 'group' },
    h('option', { value: '' }, 'Privée (vous et les administrateurs)'),
    groups.map((g) => h('option', { value: g.groupId }, `Groupe ${g.groupName}`)));
  const runCdxgen = h('input', { type: 'checkbox', checked: true });
  const vulns = h('input', { type: 'checkbox', checked: info?.vulnerabilityScanEnabled !== false,
    disabled: info?.vulnerabilityScanEnabled === false });
  const submodules = h('input', { type: 'checkbox', checked: true });
  const history = h('input', { type: 'checkbox', checked: false });
  const submit = h('button', { class: 'button primary', type: 'submit' }, 'Lancer l\'analyse');

  return h('form', {
    class: 'analysis-form',
    onsubmit: async (event) => {
      event.preventDefault();
      const list = parseTargets(targets.value);
      if (list.length === 0) {
        toast('Indiquez au moins une cible.', 'serious');
        return;
      }
      submit.disabled = true;
      try {
        await onSubmit({
          targets: list,
          branch: branch.value.trim() || null,
          runCdxgen: runCdxgen.checked,
          scanVulnerabilities: vulns.checked,
          recurseSubmodules: submodules.checked,
          scanGitHistory: history.checked,
          cdxgenTimeoutSeconds: timeout.value ? Number(timeout.value) : null,
          groupId: group.value || null,
        });
        targets.value = '';
      } catch (error) {
        toast(error.message, 'critical');
      } finally {
        submit.disabled = false;
      }
    },
  },
  h('label', { for: 'targets' }, 'Dépôts Git (https) ou dossiers autorisés'),
  targets,
  h('p', { class: 'hint' }, 'Une cible par ligne (plusieurs analyses sont lancées d\'un coup). ',
    info?.localAnalysisEnabled
      ? 'Un dossier de votre ordinateur peut aussi être analysé : collez son chemin (ex. C:\\Projets\\mon-appli).'
      : 'Dossiers locaux désactivés sur ce serveur : seuls les dépôts Git sont acceptés.',
    ' Les lignes commençant par # sont ignorées.'),
  h('div', { class: 'form-row' },
    h('div', { class: 'field' }, h('label', { for: 'branch' }, 'Branche'), branch,
      h('span', { class: 'muted small' }, 'vide = branche principale du dépôt')),
    h('div', { class: 'field' }, h('label', { for: 'timeout' }, 'Délai maximal de cdxgen (s)'), timeout,
      h('span', { class: 'muted small' }, 'au-delà, l\'analyse continue sans SBOM ; augmentez-le pour les gros dépôts')),
    h('div', { class: 'field' }, h('label', { for: 'group' }, 'Visibilité'), group,
      h('span', { class: 'muted small' }, 'modifiable ensuite (menu "Plus")'))),
  h('div', { class: 'checks' },
    h('label', { title: 'Inventaire des dépendances (SBOM) et flux cryptographiques Java/Python. Plus lent ; '
      + 'sans lui, seul le moteur de règles s\'exécute (rapide, tous langages).' }, runCdxgen,
    ' Exécuter cdxgen (SBOM + analyse de flux)'),
    h('label', { title: 'Clone aussi les dépôts référencés comme sous-modules.' }, submodules,
      ' Inclure les sous-modules Git'),
    h('label', { title: 'Cherche les secrets et les clés supprimés du code mais restés dans les anciens commits. '
      + 'Clone tout l\'historique : plus long sur les gros dépôts.' }, history,
      ' Chercher aussi dans l\'historique Git (secrets et clés supprimés)'),
    h('label', { title: 'Interroge la base publique OSV avec les noms et versions des dépendances (aucun code envoyé).' },
      vulns, ' Rechercher les vulnérabilités des dépendances (OSV)')),
  submit);
}

function capabilities(info) {
  if (!info) return null;
  // cdxgen est livré avec l'application ; s'il répond "indisponible", c'est une installation abîmée ou une
  // configuration serveur incomplète, et l'utilisateur doit le savoir avant de s'étonner d'un rapport vide.
  const cdxgenManquant = !info.cdxgenVersion || info.cdxgenVersion === 'indisponible';
  return h('div', {},
    cdxgenManquant
      ? h('p', { class: 'warning-text' }, 'cdxgen est introuvable : les analyses fonctionneront (moteur de '
        + 'règles), mais sans inventaire des dépendances ni recherche de vulnérabilités. Sur l\'application de '
        + 'bureau, réinstaller la répare ; sur un serveur, vérifier CDXGEN_COMMAND.')
      : null,
    h('p', { class: 'hint' },
      `cdxgen ${info.cdxgenVersion} - analyse de flux : ${(info.cdxgenCryptoLanguages ?? []).join(', ') || '-'} - `,
      `règles : ${(info.ruleLanguages ?? []).length} langages - `,
      info.localAnalysisEnabled ? 'dossiers locaux autorisés' : 'dossiers locaux désactivés'));
}

function jobsTable(jobs, context) {
  return h('table', { class: 'table' },
    h('thead', {}, h('tr', {},
      h('th', { scope: 'col' }, h('span', { class: 'visually-hidden' }, 'Sélection et favori')),
      ['Cible', 'Statut', 'Progression', 'Soumise', 'Durée', 'Score', ''].map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, jobs.map((job) => jobRow(job, context))));
}

/** Miroir des règles du serveur (qui reste l'autorité) : demandeur, responsable du groupe, administrateur. */
function canDelete(job, groups) {
  const me = session.current()?.user?.username;
  return session.can(PERMISSIONS.DELETE_ANY_ANALYSIS)
    || (session.can(PERMISSIONS.DELETE_OWN_ANALYSIS) && job.requestedBy === me)
    || groups.some((g) => g.manager && g.groupId === job.groupId);
}

function progressText(job, positions) {
  switch (job.status) {
    case 'queued': {
      const position = positions.get(job.id);
      return position === 1 ? 'prochaine à démarrer' : `no ${position ?? '?'} dans la file`;
    }
    case 'running':
      return `étape "${job.currentStep ?? '...'}" (${job.steps?.length ?? 0} terminée(s))`;
    case 'failed':
    case 'cancelled':
      return job.error;
    default:
      return `${job.steps?.length ?? 0} étape(s)`;
  }
}

function jobRow(job, { state, groupName, refresh, draw, positions }) {
  const style = JOB_STATUS_STYLES[job.status] ?? { icon: '•', tone: 'muted' };
  const status = { label: JOB_STATUS_LABELS[job.status] ?? job.status, ...style };
  const score = job.summary?.score;
  const favorite = state.favorites.has(job.id);
  const progress = progressText(job, positions);
  const name = job.label ?? shortTarget(job.request.target);
  return h('tr', {},
    h('td', { class: 'row-tools' },
      h('button', {
        class: `star${favorite ? ' active' : ''}`, type: 'button', 'aria-pressed': String(favorite),
        'aria-label': favorite ? `Retirer ${name} des favoris` : `Ajouter ${name} aux favoris`,
        title: favorite ? 'Retirer des favoris' : 'Ajouter aux favoris',
        onclick: async () => {
          try {
            await api.setFavorite(job.id, !favorite);
            if (favorite) state.favorites.delete(job.id);
            else state.favorites.add(job.id);
            draw();
          } catch (error) {
            toast(error.message, 'critical');
          }
        },
      }, favorite ? '★' : '☆'),
      job.status === 'succeeded' ? h('input', {
        type: 'checkbox', 'aria-label': `Sélectionner ${name} pour comparer`, checked: state.selected.has(job.id),
        disabled: !state.selected.has(job.id) && state.selected.size >= COMPARE_SIZE,
        onchange: (e) => {
          if (e.target.checked) state.selected.add(job.id);
          else state.selected.delete(job.id);
          draw();
        },
      }) : null),
    h('td', { title: job.request.target }, h('strong', { class: 'job-label' }, name),
      h('div', { class: 'muted small' }, job.request.target, job.request.branch ? ` - ${job.request.branch}` : ''),
      job.groupId ? h('span', { class: 'tag' }, groupName(job.groupId) ?? 'groupe') : null),
    h('td', {}, badge(status)),
    h('td', { class: job.status === 'failed' ? 'error-text' : job.status === 'cancelled' ? 'muted' : '' },
      progress ?? '-'),
    h('td', {}, formatDate(job.createdAt), job.requestedBy
      ? h('div', { class: 'muted small' }, `par ${job.requestedBy}`) : null),
    h('td', { title: job.status === 'running' ? 'Temps écoulé depuis le démarrage' : null },
      formatDuration(elapsed(job.startedAt, job.finishedAt))),
    h('td', {}, score == null ? '-' : h('span', { class: `score-chip tone-${scoreTone(score)}` }, `${score}/100`)),
    h('td', { class: 'actions' },
      job.status === 'succeeded' ? h('a', { class: 'button small', href: `#/report/${job.id}` }, 'Rapport') : null,
      ['failed', 'cancelled', 'running'].includes(job.status)
        ? h('a', { class: 'button small ghost', href: `#/report/${job.id}/steps`,
          title: job.status === 'running' ? 'Suivre les étapes et le journal en direct' : 'Étapes et journal' },
        job.status === 'running' ? 'Suivre' : 'Journal') : null,
      isActiveJob(job) && canDelete(job, state.groups) ? h('button', {
        class: 'button small ghost danger', type: 'button', 'aria-label': `Arrêter l'analyse ${name}`,
        title: job.status === 'queued' ? 'Retirer de la file d\'attente'
          : 'Arrêter l\'analyse (les processus en cours sont interrompus, les fichiers temporaires supprimés)',
        onclick: async (event) => {
          if (!window.confirm(`Arrêter l'analyse ${name} ? Elle pourra être relancée ensuite (menu "Plus").`)) return;
          const button = event.currentTarget;
          button.disabled = true;
          button.textContent = 'Arrêt...';
          try {
            await api.cancelAnalysis(job.id);
            toast(job.status === 'queued' ? 'Analyse retirée de la file.'
              : 'Arrêt demandé : l\'analyse s\'interrompt (jusqu\'à une minute pendant un clonage).', 'good');
            refresh();
          } catch (error) {
            button.disabled = false;
            button.textContent = 'Arrêter';
            toast(error.message, 'critical');
          }
        },
      }, job.currentStep === 'arrêt en cours' ? 'Arrêt...' : 'Arrêter') : null,
      jobMenu(job, name, { state, refresh })));
}

/** Menu "Plus" : relancer, renommer, changer la visibilité, supprimer (selon les droits). */
function jobMenu(job, name, { state, refresh }) {
  const finished = !isActiveJob(job);
  const manage = canDelete(job, state.groups);
  const rerun = finished && session.can(PERMISSIONS.RUN_ANALYSIS);
  if (!rerun && !manage) return null;
  const menu = h('details', { class: 'job-menu', open: state.openMenu === job.id });
  // Le rafraîchissement automatique redessine la liste : le menu ouvert le reste.
  menu.addEventListener('toggle', () => {
    if (menu.open) state.openMenu = job.id;
    else if (state.openMenu === job.id) state.openMenu = null;
  });
  const act = (action, success) => async () => {
    menu.open = false;
    state.openMenu = null;
    try {
      const result = await action();
      if (result === false) return;
      if (success) toast(success, 'good');
      refresh();
    } catch (error) {
      toast(error.message, 'critical');
    }
  };
  const item = (label, onclick) => h('button', { class: 'button small ghost', type: 'button', onclick }, label);
  const share = manage ? h('select', {
    'aria-label': `Visibilité de ${name}`,
    onchange: (e) => act(() => api.shareAnalysis(job.id, e.target.value || null), 'Visibilité modifiée.')(),
  }, h('option', { value: '', selected: !job.groupId }, 'Privée (vous et les administrateurs)'),
  state.groups.map((g) => h('option', { value: g.groupId, selected: g.groupId === job.groupId },
    `Partagée avec ${g.groupName}`))) : null;
  mount(menu,
    h('summary', { class: 'button small ghost', 'aria-label': `Autres actions pour ${name}` }, 'Plus ▾'),
    h('div', { class: 'job-menu-items' },
      rerun ? item('Relancer l\'analyse', act(() => api.rerunAnalysis(job.id),
        'Analyse relancée avec les mêmes paramètres.')) : null,
      manage ? item('Renommer...', act(() => {
        const label = window.prompt('Libellé de l\'analyse (vide : nom du dépôt) :', job.label ?? '');
        return label === null ? false : api.labelAnalysis(job.id, label.trim() || null);
      }, 'Libellé enregistré.')) : null,
      share,
      manage && finished ? item('Supprimer...', act(async () => {
        if (!window.confirm(`Supprimer définitivement l'analyse ${name} et ses fichiers ?`)) return false;
        return api.deleteAnalysis(job.id);
      }, 'Analyse supprimée.')) : null));
  return menu;
}
