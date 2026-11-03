// Préférences d'affichage (filtres, tris) conservées d'une visite à l'autre dans le navigateur.
//
// Elles restent locales : rien n'est envoyé au serveur, et un stockage indisponible (navigation privée,
// quota plein, Electron sans persistance) ne doit jamais casser la page - d'où les try/catch systématiques.

const KEY = 'chiffrium.prefs';
/** Au-delà, on oublie les analyses les plus anciennes : inutile de garder les filtres d'un rapport d'il y a un mois. */
const MAX_ENTRIES = 30;

function storage() {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage;
  } catch {
    return null; // Accès refusé par la politique du navigateur.
  }
}

function readAll() {
  const store = storage();
  if (!store) return {};
  try {
    const raw = JSON.parse(store.getItem(KEY) ?? '{}');
    return raw && typeof raw === 'object' ? raw : {};
  } catch {
    return {};
  }
}

function writeAll(all) {
  const store = storage();
  if (!store) return;
  try {
    const kept = Object.entries(all)
      .sort((a, b) => (b[1]?.at ?? 0) - (a[1]?.at ?? 0))
      .slice(0, MAX_ENTRIES);
    store.setItem(KEY, JSON.stringify(Object.fromEntries(kept)));
  } catch {
    // Quota dépassé : on abandonne l'écriture, les préférences repartiront des valeurs par défaut.
  }
}

/**
 * @param {string} section famille de préférence, par exemple `report-filters`
 * @param {string} id      clé dans la famille, par exemple l'identifiant d'analyse
 */
export function readPref(section, id, fallback = null) {
  const entry = readAll()[`${section}:${id}`];
  return entry && 'value' in entry ? entry.value : fallback;
}

export function writePref(section, id, value) {
  const all = readAll();
  all[`${section}:${id}`] = { value, at: Date.now() };
  writeAll(all);
}

export function clearPref(section, id) {
  const all = readAll();
  delete all[`${section}:${id}`];
  writeAll(all);
}
