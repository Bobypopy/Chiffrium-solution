import { api } from '../api.js';
import { emptyState, h, mount } from '../ui/dom.js';

/** Licence, composants tiers, données personnelles traitées et services externes contactés. */
export async function renderAbout(container) {
  mount(container, h('p', { class: 'muted' }, 'Chargement...'));
  let about;
  try {
    about = await api.about();
  } catch (error) {
    mount(container, emptyState(error.message));
    return;
  }
  const organization = about.organization ?? {};
  const components = about.thirdParty?.components ?? [];
  const data = about.thirdParty?.data ?? [];
  mount(container,
    h('section', { class: 'card' },
      h('h1', {}, `${about.product} ${about.version}`),
      h('p', {}, about.license),
      organization.name ? h('p', {}, 'Outil mis à disposition par ', h('strong', {}, organization.name), '.') : null),
    organization.usageNotice ? h('section', { class: 'card' }, h('h2', {}, 'Charte d\'utilisation'),
      h('p', { class: 'prewrap' }, organization.usageNotice)) : null,
    h('section', { class: 'card' },
      h('h2', {}, 'Données personnelles'),
      h('ul', {},
        h('li', {}, 'Comptes : identifiant, nom affiché, e-mail (facultatif), rôle, groupes, dates de connexion.'),
        h('li', {}, 'Journal d\'audit : actions sensibles avec l\'auteur, la date et l\'adresse IP d\'origine '
          + '(finalité : sécurité et traçabilité).'),
        h('li', {}, 'Code analysé : peut contenir des données personnelles ou des secrets ; les rapports sont chiffrés '
          + 'et les secrets détectés caviardés.'),
        h('li', {}, 'Aucune donnée n\'est transmise à l\'éditeur de l\'outil ; aucune mesure d\'audience.')),
      organization.privacyContact
        ? h('p', {}, 'Pour exercer vos droits (accès, rectification, effacement, limitation) : ',
          h('strong', {}, organization.privacyContact), '.')
        : h('p', { class: 'hint' }, 'Contact données personnelles non renseigné (Administration -> Paramètres).')),
    h('section', { class: 'card' },
      h('h2', {}, 'Services externes contactés'),
      h('p', { class: 'hint' }, 'Seuls des identifiants techniques (nom et version de paquet, identifiant CVE) sont '
        + 'envoyés ; jamais de code source ni de donnée personnelle.'),
      h('ul', {}, (about.externalServices ?? []).map((s) => h('li', {}, s)))),
    h('section', { class: 'card table-wrap' },
      h('h2', {}, 'Composants tiers'),
      h('table', { class: 'table' },
        h('thead', {}, h('tr', {}, ['Composant', 'Licence'].map((t) => h('th', { scope: 'col' }, t)))),
        h('tbody', {}, components.map((c) => h('tr', {},
          h('td', {}, h('a', { href: c.url, target: '_blank', rel: 'noopener noreferrer' }, c.name)),
          h('td', {}, c.license)))))),
    h('section', { class: 'card' },
      h('h2', {}, 'Sources de données'),
      h('ul', {}, data.map((d) => h('li', {},
        h('a', { href: d.url, target: '_blank', rel: 'noopener noreferrer' }, d.name), ` - ${d.terms}`)))));
}

/** Charte d'utilisation affichée sous le formulaire de connexion, si l'organisation l'a renseignée. */
export async function usageNotice() {
  try {
    const about = await api.about();
    return about.organization?.usageNotice ?? null;
  } catch {
    return null;
  }
}
