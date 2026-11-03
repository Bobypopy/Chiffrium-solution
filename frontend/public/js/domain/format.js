// Mise en forme des valeurs (dates, durées, cibles).

const MS_PER_SECOND = 1000;
const SECONDS_PER_MINUTE = 60;
const DATE_FORMAT = new Intl.DateTimeFormat('fr-FR', { dateStyle: 'short', timeStyle: 'short' });

export function formatDate(iso) {
  if (!iso) return '-';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '-' : DATE_FORMAT.format(date);
}

export function formatDuration(ms) {
  if (ms == null || Number.isNaN(ms)) return '-';
  if (ms < MS_PER_SECOND) return `${ms} ms`;
  const seconds = ms / MS_PER_SECOND;
  if (seconds < SECONDS_PER_MINUTE) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / SECONDS_PER_MINUTE);
  return `${minutes} min ${Math.round(seconds % SECONDS_PER_MINUTE)} s`;
}

/** Durée entre deux instants ISO (ou jusqu'à maintenant). */
export function elapsed(startIso, endIso, now = Date.now()) {
  if (!startIso) return null;
  const end = endIso ? new Date(endIso).getTime() : now;
  return Math.max(0, end - new Date(startIso).getTime());
}

/** Nom court d'une cible : dernier segment d'une URL Git ou d'un chemin. */
export function shortTarget(target) {
  if (!target) return '-';
  const trimmed = target.replace(/[/\\]+$/, '');
  const last = trimmed.split(/[/\\]/).pop() ?? trimmed;
  return last.endsWith('.git') ? last.slice(0, -'.git'.length) : last;
}

/** Découpe une saisie multi-lignes en cibles (une par ligne, lignes vides et commentaires ignorés). */
export function parseTargets(text) {
  return [...new Set(String(text ?? '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#')))];
}

export function plural(count, singular, pluralForm = `${singular}s`) {
  return `${count} ${count > 1 ? pluralForm : singular}`;
}
