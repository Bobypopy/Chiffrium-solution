// Configuration de construction des installateurs (electron-builder).
// Le dépôt de publication des mises à jour est lu dans l'environnement : rien n'est lié à un compte précis.
//   UPDATE_OWNER / UPDATE_REPO : dépôt GitHub hébergeant les "releases" (défaut : GITHUB_REPOSITORY en CI)

const [ciOwner, ciRepo] = (process.env.GITHUB_REPOSITORY ?? '/').split('/');
const owner = process.env.UPDATE_OWNER || ciOwner;
const repo = process.env.UPDATE_REPO || ciRepo;

module.exports = {
  appId: 'io.chiffrium.desktop',
  productName: 'Chiffrium',
  directories: { output: 'dist', buildResources: 'build' },
  // Les binaires optionnels de cdxgen (trivy, osquery...) servent à l'analyse d'images conteneur, pas du code
  // source : exclus (environ 45 Mo de moins).
  files: ['src/**/*', 'package.json', 'node_modules/**/*', '!node_modules/@cyclonedx/cdxgen-plugins-bin*/**'],
  extraFiles: [
    { from: '../LICENSE', to: 'LICENSE.txt' },
    { from: '../THIRD-PARTY-NOTICES.md', to: 'THIRD-PARTY-NOTICES.md' },
  ],
  // Ressources préparées par scripts/prepare.mjs : JRE minimal (jlink), backend et interface.
  extraResources: [
    { from: 'resources/jre', to: 'jre' },
    { from: 'resources/backend', to: 'backend' },
    { from: 'resources/frontend', to: 'frontend' },
  ],
  // cdxgen est exécuté par un processus Node séparé : lui et ses dépendances doivent être hors de l'archive asar.
  asarUnpack: ['node_modules/**/*'],
  win: {
    target: [{ target: 'nsis', arch: ['x64'] }],
    icon: 'build/icon.ico',
  },
  nsis: {
    // Nom sans espaces, identique à celui de la release GitHub et de latest.yml : l'installateur signé par
    // SignPath (scripts/after-sign.mjs) se retrouve ainsi sous le même nom partout.
    artifactName: '${productName}-Setup-${version}.${ext}',
    // Licence affichée (et à accepter) pendant l'installation ; copiée par scripts/prepare.mjs.
    license: 'resources/license.txt',
    oneClick: false,
    perMachine: false,
    allowToChangeInstallationDirectory: true,
    createDesktopShortcut: true,
    deleteAppDataOnUninstall: false,
  },
  linux: {
    target: ['AppImage', 'deb'],
    category: 'Development',
    icon: 'build/icon.png',
    maintainer: 'Les auteurs de Chiffrium',
    // Description courte du paquet : sans elle, "Description:" reste vide dans le .deb (contraire à la
    // politique Debian, et le gestionnaire de paquets n'affiche aucun résumé).
    synopsis: 'Inventaire cryptographique (CBOM) et constats de sécurité',
    syncDesktopName: true,
  },
  deb: {
    priority: 'optional',
  },
  // Sans dépôt de publication (construction locale), pas de métadonnées de mise à jour.
  publish: owner && repo ? { provider: 'github', owner, repo, releaseType: 'release' } : null,
};
