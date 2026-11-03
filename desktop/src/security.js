// Règles de sécurité de la fenêtre, isolées pour être testées sans Electron.

/**
 * Navigation autorisée dans la fenêtre principale : l'application elle-même, et les pages https du
 * fournisseur d'identité pendant une connexion SSO. Tout le reste (file:, javascript:, http distant...) est refusé.
 */
function isAllowedNavigation(url, appOrigin) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  return parsed.origin === appOrigin || parsed.protocol === 'https:';
}

/** Liens ouverts dans le navigateur du système (références CVE, documentation) : https uniquement. */
function isExternalLink(url) {
  try {
    return new URL(url).protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Pages autorisées à utiliser le pont vers le processus principal : l'interface de l'application et l'écran
 * d'accueil embarqué (file:). Une page https tierce (fournisseur SSO) est refusée.
 */
function isTrustedSender(senderUrl, appOrigin) {
  let parsed;
  try {
    parsed = new URL(senderUrl);
  } catch {
    return false;
  }
  return parsed.protocol === 'file:' || (appOrigin != null && parsed.origin === appOrigin);
}

/** Politique de sécurité du contenu ajoutée aux réponses de l'application (défense en profondeur). */
const CONTENT_SECURITY_POLICY = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
  + "object-src 'none'; frame-ancestors 'none'; base-uri 'none'";

module.exports = { isAllowedNavigation, isExternalLink, isTrustedSender, CONTENT_SECURITY_POLICY };
