import { api } from '../api.js';
import { PRIMITIVE_LABELS, STATUSES, label, statusInfo } from '../domain/labels.js';
import {
  catalogDiff, describeDiff, describePolicy, filterCatalog, oidInfoUrl, quantumPosture, sortCatalog, suggestOids,
} from '../domain/catalog.js';
import { formatDate } from '../domain/format.js';
import { PERMISSIONS, session } from '../session.js';
import { badge, emptyState, h, mount, rememberScroll, toast } from '../ui/dom.js';

const PRIMITIVES = Object.keys(PRIMITIVE_LABELS);
const ID_PATTERN = '[a-z0-9][a-z0-9.\\-]*';
const MIN_YEAR = 2000;
const MAX_YEAR = 2100;

const COLUMNS = [
  { key: 'name', label: 'Algorithme' },
  { key: 'primitive', label: 'Famille' },
  { key: 'status', label: 'Statut' },
  { key: 'quantum', label: 'Quantique' },
  { key: 'validity', label: 'Validité' },
  { key: 'oid', label: 'OID' },
];
const MAX_IMPORT_BYTES = 5 * 1024 * 1024;

/** Consultation, tri et édition du catalogue d'algorithmes (politique cryptographique). */
export async function renderCatalog(container) {
  mount(container, h('p', { class: 'muted' }, 'Chargement du catalogue...'));
  let catalog;
  try {
    catalog = await api.getCatalog();
  } catch (error) {
    mount(container, emptyState(`Catalogue indisponible : ${error.message}`));
    return;
  }
  const canEdit = session.can(PERMISSIONS.EDIT_CATALOG);
  const canPropose = !canEdit && session.can(PERMISSIONS.REQUEST_CATALOG_CHANGE);
  const requestsPanel = h('section', { class: 'card', hidden: true });
  let groups = [];
  const tableBody = h('tbody');
  const headRow = h('tr');
  const count = h('span', { class: 'muted small' });
  const editor = h('div', { class: 'card editor', hidden: true });
  const tableWrap = h('section', { class: 'card table-wrap' });
  /** Position de lecture avant l'ouverture du formulaire, pour y revenir à la fermeture. */
  let restorePosition = null;
  const filters = { text: '', status: '', primitive: '', quantum: '', type: '' };
  const sort = { key: 'primitive', direction: 'asc' };

  const reload = async () => {
    catalog = await api.getCatalog();
    draw();
  };

  const drawHead = () => mount(headRow, COLUMNS.map((column) => {
    const active = sort.key === column.key;
    const ariaSort = active ? (sort.direction === 'asc' ? 'ascending' : 'descending') : 'none';
    return h('th', { scope: 'col', 'aria-sort': ariaSort },
      h('button', {
        class: 'sort-button', type: 'button',
        onclick: () => {
          sort.direction = active && sort.direction === 'asc' ? 'desc' : 'asc';
          sort.key = column.key;
          draw();
        },
      }, column.label, h('span', { 'aria-hidden': 'true' }, active ? (sort.direction === 'asc' ? ' ▲' : ' ▼') : ' ↕')));
  }), canEdit || canPropose ? h('th', { scope: 'col' }, h('span', { class: 'visually-hidden' }, 'Actions')) : null);

  const remove = async (algorithm) => {
    if (!window.confirm(`Supprimer "${algorithm.name}" du catalogue ? Les prochaines analyses ne le `
      + 'reconnaîtront plus.')) return;
    try {
      await api.deleteAlgorithm(algorithm.id);
      toast(`"${algorithm.name}" supprimé.`, 'good');
      await reload();
    } catch (error) {
      toast(error.message, 'critical');
    }
  };

  const draw = () => {
    drawHead();
    const rows = sortCatalog(filterCatalog(catalog.algorithms, filters), sort.key, sort.direction);
    count.textContent = `${rows.length} / ${catalog.algorithms.length} entrées`;
    mount(tableBody, rows.length ? rows.map((algorithm) => h('tr', {},
      h('td', {}, h('strong', {}, algorithm.name), h('div', { class: 'muted small' }, algorithm.id)),
      h('td', {}, label(PRIMITIVE_LABELS, algorithm.primitive)),
      h('td', {}, badge(statusInfo(algorithm.status)),
        // Nuance essentielle : AES est recommandé, mais interdit en dessous de 128 bits.
        (algorithm.keySizeRules ?? []).length
          ? h('div', { class: 'muted small' }, (algorithm.keySizeRules ?? [])
            .map((rule) => `< ${rule.below} bits : ${statusInfo(rule.status).label.toLowerCase()}`).join(' - '))
          : null),
      h('td', {}, quantumCell(algorithm)),
      h('td', { class: 'small' }, validity(algorithm)),
      h('td', { class: 'small mono' }, algorithm.oids.length ? algorithm.oids.map((o, index) => [index ? ', ' : '',
        h('a', { href: oidInfoUrl(o.oid), target: '_blank', rel: 'noopener noreferrer',
          title: `${o.description ?? ''} - fiche sur oid-base.com`.trim() }, o.oid)]) : '-'),
      canEdit ? h('td', { class: 'actions' },
        h('button', { class: 'button small ghost', type: 'button', onclick: () => openEditor(algorithm) }, 'Modifier'),
        h('button', {
          class: 'button small ghost', type: 'button', 'aria-label': `Supprimer ${algorithm.name}`,
          onclick: () => remove(algorithm),
        }, 'Supprimer'))
        : canPropose ? h('td', { class: 'actions' },
          h('button', { class: 'button small ghost', type: 'button', onclick: () => openProposal(algorithm) },
            'Proposer une modification'),
          h('button', { class: 'button small ghost', type: 'button', onclick: () => proposeDeletion(algorithm) },
            'Proposer le retrait')) : null))
      : h('tr', {}, h('td', { colspan: COLUMNS.length + 1 }, emptyState('Aucune entrée ne correspond aux filtres.'))));
  };

  const closeEditor = () => {
    editor.hidden = true;
    restorePosition?.();
    restorePosition = null;
  };

  const openEditor = (algorithm) => {
    restorePosition = rememberScroll(tableWrap);
    editor.hidden = false;
    mount(editor, editorForm(algorithm, async (definition) => {
      await api.saveAlgorithm(definition);
      toast(`"${definition.name}" enregistré. Les prochaines analyses utiliseront cette politique.`, 'good');
      const retour = restorePosition;
      editor.hidden = true;
      restorePosition = null;
      await reload();
      retour?.();
    }, closeEditor));
    editor.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  };

  const drawRequests = async () => {
    try {
      const requests = await api.listCatalogRequests();
      requestsPanel.hidden = requests.length === 0 && !canPropose;
      mount(requestsPanel, requestsSection(requests, canEdit, async () => {
        await drawRequests();
        await reload();
      }));
    } catch (error) {
      mount(requestsPanel, emptyState(error.message));
    }
  };

  const openProposal = (algorithm) => {
    restorePosition = rememberScroll(tableWrap);
    editor.hidden = false;
    mount(editor, editorForm(algorithm, async (definition, extras) => {
      await api.submitCatalogRequest({ kind: algorithm ? 'update' : 'create', algorithmId: definition.id,
        proposal: definition, ...extras });
      toast('Demande envoyée aux administrateurs.', 'good');
      const retour = restorePosition;
      editor.hidden = true;
      restorePosition = null;
      await drawRequests();
      retour?.();
    }, closeEditor, { proposal: true, groups }));
    editor.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  };

  const proposeDeletion = async (algorithm) => {
    const justification = window.prompt(`Pourquoi retirer "${algorithm.name}" du catalogue ?`);
    if (!justification?.trim()) return;
    try {
      await api.submitCatalogRequest({ kind: 'delete', algorithmId: algorithm.id, justification });
      toast('Demande envoyée aux administrateurs.', 'good');
      await drawRequests();
    } catch (error) {
      toast(error.message, 'critical');
    }
  };

  const importInput = h('input', {
    type: 'file', accept: 'application/json,.json', hidden: true,
    onchange: async (event) => {
      const file = event.target.files[0];
      event.target.value = '';
      if (!file) return;
      if (file.size > MAX_IMPORT_BYTES) {
        toast('Fichier trop volumineux.', 'critical');
        return;
      }
      try {
        const imported = JSON.parse(await file.text());
        // Montrer les écarts avant d'écraser : un import à l'aveugle fait disparaître sans bruit des
        // entrées ajoutées localement.
        const diff = catalogDiff(catalog, imported);
        const politique = describePolicy(imported.policy);
        const details = diff.identical
          ? ['Contenu identique au catalogue actuel.']
          : describeDiff(diff);
        if (!window.confirm([
          `Remplacer le catalogue actuel (${catalog.algorithms.length} entrées) par ${imported.algorithms?.length ?? 0} entrée(s) ?`,
          politique ?? 'Fichier sans politique publiée (export d\'un catalogue local).',
          ...details,
          'Une sauvegarde de la version précédente est conservée par le serveur.',
        ].join('\n\n'))) return;
        await api.importCatalog(imported);
        toast('Catalogue importé.', 'good');
        await reload();
      } catch (error) {
        toast(error instanceof SyntaxError ? 'Fichier JSON invalide.' : error.message, 'critical');
      }
    },
  });

  const select = (key, placeholder, options) => h('select', {
    'aria-label': placeholder, onchange: (e) => { filters[key] = e.target.value; draw(); },
  }, h('option', { value: '' }, placeholder), options.map(([value, text]) => h('option', { value }, text)));

  mount(container,
    h('section', { class: 'card' },
      h('div', { class: 'card-header' },
        h('h2', {}, `Catalogue d'algorithmes (${catalog.algorithms.length})`),
        h('div', { class: 'actions' },
          h('button', {
            class: 'button ghost', type: 'button',
            onclick: () => api.exportCatalog().catch((e) => toast(e.message, 'critical')),
          }, 'Exporter'),
          canEdit ? h('button', {
            class: 'button ghost', type: 'button',
            title: 'Figer le catalogue actuel comme politique d\'entreprise, à diffuser aux autres installations',
            onclick: async () => {
              const propose = catalog.policy?.name ?? 'Politique d\'entreprise';
              const name = window.prompt('Nom de la politique à publier :', propose);
              if (name === null) return;
              try {
                const published = await api.publishCatalog(name);
                toast(`Politique "${published.policy.name}" publiée en version ${published.policy.version}.`,
                  'good');
                await reload();
              } catch (error) {
                toast(error.message, 'critical');
              }
            },
          }, 'Publier la politique') : null,
          canEdit ? [importInput,
            h('button', { class: 'button ghost', type: 'button', onclick: () => importInput.click() }, 'Importer'),
            h('button', { class: 'button primary', type: 'button', onclick: () => openEditor(null) },
              'Ajouter un algorithme')] : null,
          canPropose ? h('button', { class: 'button primary', type: 'button', onclick: () => openProposal(null) },
            'Proposer un algorithme') : null)),
      catalog.policy
        ? h('p', { class: 'muted small' }, describePolicy(catalog.policy),
          catalog.policy.publishedAt ? ` - le ${formatDate(catalog.policy.publishedAt)}` : '')
        : h('p', { class: 'muted small' }, 'Catalogue local : aucune politique publiée. "Publier la politique" '
          + 'fige une version numérotée, exportable vers les autres installations.'),
      h('p', { class: 'hint' }, 'Source de vérité pour la détection (alias) et l\'évaluation (statuts, années de ',
        'transition NIST, tailles de clé, résistance quantique). Modes, bourrages et courbes : ',
        `${catalog.modes.length} / ${catalog.paddings.length} / ${catalog.curves.length} entrées.`),
      h('div', { class: 'filters' },
        h('input', {
          type: 'search', placeholder: 'Filtrer (nom, alias, OID, mot-clé de la note)...', 'aria-label': 'Filtrer le catalogue',
          oninput: (e) => { filters.text = e.target.value; draw(); },
        }),
        select('status', 'Tous les statuts', STATUSES.map((s) => [s.id, s.label])),
        select('primitive', 'Toutes les familles', PRIMITIVES.map((p) => [p, label(PRIMITIVE_LABELS, p)])),
        select('type', 'Algorithmes et protocoles', [['algorithm', 'Algorithmes'], ['protocol', 'Protocoles']]),
        select('quantum', 'Quantique : tous', [['shor', 'Cassés par Shor'],
          ['pqc', 'Résistants (post-quantique)'], ['grover', 'Symétriques (marge Grover)'],
          ['obsolete', 'Déjà à proscrire']]),
        count)),
    requestsPanel,
    editor,
    mount(tableWrap, h('table', { class: 'table' }, h('thead', {}, headRow), tableBody)));
  draw();
  drawRequests();
  if (canPropose) api.myGroups().then((mine) => { groups = mine; }).catch(() => {});
}

const REQUEST_STATUS = Object.freeze({
  pending: { label: 'En attente', icon: '...', tone: 'neutral' },
  approved: { label: 'Acceptée', icon: '✓', tone: 'good' },
  rejected: { label: 'Refusée', icon: '✕', tone: 'critical' },
  withdrawn: { label: 'Retirée', icon: '-', tone: 'muted' },
});
const REQUEST_KINDS = Object.freeze({ create: 'Ajout', update: 'Modification', delete: 'Retrait' });

/** Demandes : file de validation (administrateurs) ou suivi de ses demandes (autres utilisateurs). */
function requestsSection(requests, reviewer, onChange) {
  const pending = requests.filter((r) => r.status === 'pending');
  const act = (action) => async () => {
    try {
      await action();
      await onChange();
    } catch (error) {
      toast(error.message, 'critical');
    }
  };
  return [
    h('h2', {}, reviewer ? `Demandes de modification (${pending.length} en attente)` : 'Mes demandes'),
    requests.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
      h('thead', {}, h('tr', {}, ['Demande', 'Justification', 'État', ''].map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', {}, requests.map((r) => h('tr', {},
        h('td', {}, h('strong', {}, `${REQUEST_KINDS[r.kind] ?? r.kind} - ${r.algorithmId}`),
          r.proposal ? h('div', { class: 'small' }, `${r.proposal.name} -> `, badge(statusInfo(r.proposal.status))) : null,
          h('div', { class: 'muted small' }, `par ${r.requestedBy} le ${formatDate(r.createdAt)}`)),
        h('td', { class: 'small' }, r.justification,
          r.reviewComment ? h('p', { class: 'recommendation' }, `${r.reviewedBy} : ${r.reviewComment}`) : null),
        h('td', {}, badge(REQUEST_STATUS[r.status] ?? REQUEST_STATUS.pending)),
        h('td', { class: 'actions' }, r.status !== 'pending' ? null : reviewer ? [
          h('button', { class: 'button small primary', type: 'button', onclick: act(() => api.reviewCatalogRequest(r.id,
            true, window.prompt('Commentaire (facultatif) :') ?? null)) }, 'Accepter'),
          h('button', { class: 'button small ghost', type: 'button', onclick: act(async () => {
            const reason = window.prompt('Motif du refus (communiqué au demandeur) :');
            if (reason?.trim()) await api.reviewCatalogRequest(r.id, false, reason);
          }) }, 'Refuser'),
        ] : r.requestedBy === session.current()?.user?.username ? h('button', {
          class: 'button small ghost', type: 'button', onclick: act(() => api.withdrawCatalogRequest(r.id)),
        }, 'Retirer') : null)))))) : emptyState('Aucune demande pour le moment.'),
  ];
}

/** Cellule "Quantique" : le libellé est cliquable au survol pour expliquer ce qu'il signifie. */
function quantumCell(algorithm) {
  const posture = quantumPosture(algorithm);
  return h('span', { class: `tag tone-${posture.tone}`, title: posture.hint }, posture.label);
}

function validity(algorithm) {
  const parts = [];
  if (algorithm.deprecatedAfter) parts.push(`déprécié après ${algorithm.deprecatedAfter}`);
  if (algorithm.disallowedAfter) parts.push(`interdit après ${algorithm.disallowedAfter}`);
  for (const rule of algorithm.keySizeRules ?? []) {
    parts.push(`< ${rule.below} bits : ${statusInfo(rule.status).label.toLowerCase()}${rule.fromYear ? ` dès ${rule.fromYear}` : ''}`);
  }
  return parts.join(' - ') || '-';
}

/**
 * @param {object} options { proposal: vrai pour une demande soumise à validation, groups: groupes de l'utilisateur }
 */
function editorForm(existing, onSave, onCancel, options = {}) {
  const value = existing ?? { id: '', name: '', primitive: 'unknown', status: 'unknown', quantumVulnerable: false,
    aliases: [], tokens: [], oids: [], keySizeRules: [], references: [] };
  const field = (id, text, input) => h('div', { class: 'field' }, h('label', { for: id }, text), input);
  const idInput = h('input', { id: 'algo-id', required: true, pattern: ID_PATTERN, value: value.id, readonly: Boolean(existing) });
  const name = h('input', { id: 'algo-name', required: true, value: value.name });
  const primitive = h('select', { id: 'algo-primitive' },
    PRIMITIVES.map((p) => h('option', { value: p, selected: p === value.primitive }, label(PRIMITIVE_LABELS, p))));
  const status = h('select', { id: 'algo-status' },
    STATUSES.map((s) => h('option', { value: s.id, selected: s.id === value.status }, s.label)));
  const quantum = h('input', { type: 'checkbox', checked: value.quantumVulnerable });
  const year = (id, v) => h('input', { id, type: 'number', min: MIN_YEAR, max: MAX_YEAR, value: v ?? '' });
  const deprecatedAfter = year('algo-deprecated', value.deprecatedAfter);
  const disallowedAfter = year('algo-disallowed', value.disallowedAfter);
  const aliases = h('input', { id: 'algo-aliases', value: value.aliases.join(', '),
    placeholder: 'formes compactes en minuscules, ex. sha256, sha2256' });
  const oids = h('input', { id: 'algo-oids', value: value.oids.map((o) => o.oid).join(', '),
    placeholder: 'ex. 2.16.840.1.101.3.4.2.1', 'aria-describedby': 'algo-oids-help' });
  const oidHelp = h('div', { id: 'algo-oids-help', class: 'muted small oid-help' });
  let suggestion = null;
  let autoFilled = null;
  const note = h('textarea', { id: 'algo-note', rows: 2 }, value.note ?? '');
  const recommendation = h('textarea', { id: 'algo-reco', rows: 2 }, value.recommendation ?? '');
  const errors = h('ul', { class: 'error-text' });
  const justification = h('textarea', { id: 'algo-justification', rows: 3, required: true,
    placeholder: 'Pourquoi ce changement ? (référence normative, décision interne, besoin métier...)' });
  const group = h('select', { id: 'algo-group' }, h('option', { value: '' }, 'Aucun'),
    (options.groups ?? []).map((g) => h('option', { value: g.groupId }, g.groupName)));

  const list = (text) => text.split(',').map((s) => s.trim()).filter(Boolean);

  /** Liens de vérification des OID saisis, et origine de la proposition le cas échéant. */
  const drawOidHelp = () => {
    const current = list(oids.value);
    mount(oidHelp,
      suggestion && autoFilled === oids.value
        ? h('span', {}, `Proposé d'après "${suggestion.source.name}" (référence intégrée) : modifiable. `) : null,
      current.length ? ['Vérifier : ', current.map((oid, index) => [index ? ' - ' : '',
        h('a', { href: oidInfoUrl(oid), target: '_blank', rel: 'noopener noreferrer' }, `${oid}`)])]
        : h('span', {}, 'Aucun OID. Les protocoles et certains algorithmes n\'en ont pas. ',
          h('a', { href: 'https://oid-base.com/', target: '_blank', rel: 'noopener noreferrer' },
            'Chercher sur oid-base.com')));
  };

  /**
   * Proposition pendant la saisie : seulement si le champ OID est vide ou contient encore la proposition
   * précédente ; une valeur tapée par l'utilisateur n'est jamais remplacée.
   */
  const propose = () => {
    if (!reference) return;
    const found = suggestOids(reference, { id: idInput.value, name: name.value, aliases: list(aliases.value) });
    if (oids.value.trim() === '' || oids.value === autoFilled) {
      suggestion = found;
      autoFilled = found ? found.oids.map((o) => o.oid).join(', ') : null;
      oids.value = autoFilled ?? '';
    }
    drawOidHelp();
  };
  let reference = null;
  api.catalogReferenceOids().then((items) => {
    reference = items;
    if (!existing?.oids?.length) propose();
  }).catch(() => {});
  for (const input of [idInput, name, aliases]) input.addEventListener('input', propose);
  oids.addEventListener('input', drawOidHelp);
  drawOidHelp();

  return h('form', {
    onsubmit: async (event) => {
      event.preventDefault();
      const definition = {
        ...value,
        id: idInput.value.trim(),
        name: name.value.trim(),
        primitive: primitive.value,
        status: status.value,
        quantumVulnerable: quantum.checked,
        deprecatedAfter: deprecatedAfter.value ? Number(deprecatedAfter.value) : null,
        disallowedAfter: disallowedAfter.value ? Number(disallowedAfter.value) : null,
        aliases: list(aliases.value).map((a) => a.toLowerCase()),
        oids: list(oids.value).map((oid) => value.oids.find((o) => o.oid === oid)
          ?? suggestion?.oids.find((o) => o.oid === oid) ?? { oid, description: 'Ajout manuel' }),
        note: note.value.trim() || null,
        recommendation: recommendation.value.trim() || null,
      };
      try {
        await onSave(definition, { justification: justification.value.trim(), groupId: group.value || null });
      } catch (error) {
        mount(errors, h('li', {}, error.message), (error.details ?? []).map((d) => h('li', {}, d)));
      }
    },
  },
  h('h2', {}, options.proposal
    ? (existing ? `Proposer une modification de "${existing.name}"` : 'Proposer un nouvel algorithme')
    : (existing ? `Modifier "${existing.name}"` : 'Nouvel algorithme')),
  options.proposal ? h('p', { class: 'hint' }, 'Votre proposition sera examinée par un administrateur ; vous serez ',
    'informé de sa décision dans "Mes demandes".') : null,
  h('div', { class: 'form-grid' },
    field('algo-id', 'Identifiant', idInput), field('algo-name', 'Nom affiché', name),
    field('algo-primitive', 'Primitive', primitive), field('algo-status', 'Statut', status),
    field('algo-deprecated', 'Déprécié après (année)', deprecatedAfter),
    field('algo-disallowed', 'Interdit après (année)', disallowedAfter),
    field('algo-aliases', 'Alias de détection', aliases),
    h('div', { class: 'field' }, h('label', { for: 'algo-oids' }, 'OID'), oids, oidHelp)),
  h('label', { class: 'inline-check' }, quantum,
    ' Cassé par un ordinateur quantique (algorithme de Shor : RSA, Diffie-Hellman, courbes elliptiques)'),
  field('algo-note', 'Note', note),
  field('algo-reco', 'Recommandation', recommendation),
  options.proposal ? [field('algo-justification', 'Justification', justification),
    options.groups?.length ? field('algo-group', 'Au nom du groupe', group) : null] : null,
  errors,
  h('div', { class: 'actions' },
    h('button', { class: 'button primary', type: 'submit' }, options.proposal ? 'Envoyer la demande' : 'Enregistrer'),
    h('button', { class: 'button ghost', type: 'button', onclick: onCancel }, 'Annuler')));
}
