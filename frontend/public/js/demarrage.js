// Filet de sécurité : sans lui, un seul fichier manquant laisse une fenêtre vide et muette.
//
// Script classique et sans import, pour fonctionner justement quand le chargement des modules échoue.
// main.js appelle window.__demarrageOk() dès que le routeur prend la main.

(function () {
  var DELAI_MS = 8000;
  var erreurs = [];
  var demarre = false;

  /** Les erreurs de chargement de ressource ne remontent pas : on les attrape à la capture. */
  window.addEventListener('error', function (evenement) {
    var cible = evenement.target;
    if (cible && cible !== window && (cible.src || cible.href)) {
      erreurs.push('fichier non chargé : ' + (cible.src || cible.href));
    } else if (evenement.message) {
      erreurs.push(evenement.message);
    }
    setTimeout(panne, 500);
  }, true);

  window.addEventListener('unhandledrejection', function (evenement) {
    erreurs.push(String((evenement.reason && evenement.reason.message) || evenement.reason));
  });

  window.__demarrageOk = function () {
    demarre = true;
  };

  /** Fichiers demandés par la page et refusés par le serveur (404 d'une livraison incomplète). */
  function manquants() {
    try {
      return performance.getEntriesByType('resource')
        .filter(function (entree) { return entree.responseStatus >= 400; })
        .map(function (entree) {
          return entree.name.replace(location.origin + '/', '') + ' (' + entree.responseStatus + ')';
        });
    } catch (erreur) {
      return [];
    }
  }

  function ligne(texte, classe) {
    var p = document.createElement('p');
    if (classe) p.className = classe;
    p.textContent = texte;
    return p;
  }

  function panne() {
    if (demarre) return;
    var app = document.getElementById('app');
    if (!app || app.children.length > 0) return;

    var section = document.createElement('section');
    section.className = 'card error-box';

    var titre = document.createElement('h2');
    titre.textContent = "L'interface n'a pas pu démarrer";
    section.appendChild(titre);

    section.appendChild(ligne("Un fichier de l'application n'a pas pu être chargé. L'installation est"
      + ' probablement incomplète : réinstallez la dernière version, vos données et vos analyses sont'
      + ' conservées.'));

    // Un module qui échoue ne nomme que le script de tête (js/main.js), jamais l'import fautif. Les mesures
    // de chargement, elles, portent le code HTTP : on y retrouve le fichier réellement manquant.
    var absents = manquants();
    var detail = absents.length ? 'Fichier(s) manquant(s) : ' + absents.slice(0, 5).join(' / ')
      : erreurs.slice(0, 5).join(' / ');
    if (detail) section.appendChild(ligne(detail, 'muted small'));

    section.appendChild(ligne("Le détail complet est dans le journal de l'application (Aide > Journal, ou"
      + ' %APPDATA%\\Chiffrium\\desktop.log).', 'muted small'));

    app.appendChild(section);
  }

  // Deux déclencheurs : une erreur de chargement (immédiat, ci-dessus) et un démarrage qui n'arrive jamais.
  setTimeout(panne, DELAI_MS);
})();
