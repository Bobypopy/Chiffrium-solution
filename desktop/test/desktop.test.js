const assert = require('node:assert/strict');
const { test } = require('node:test');

const { backendEnvironment, freePort } = require('../src/backend');
const { atomShimScript, launcherScripts, shimScript } = require('../src/cdxgen');
const { isAllowedNavigation, isExternalLink, isTrustedSender } = require('../src/security');

const ORIGIN = 'http://127.0.0.1:43123';

test('la fenêtre ne navigue que vers l\'application ou un fournisseur SSO en https', () => {
  assert.ok(isAllowedNavigation(`${ORIGIN}/#/analyses`, ORIGIN));
  assert.ok(isAllowedNavigation('https://login.example.test/authorize?x=1', ORIGIN));
  assert.ok(!isAllowedNavigation('http://evil.example.test/', ORIGIN));
  assert.ok(!isAllowedNavigation('file:///etc/passwd', ORIGIN));
  assert.ok(!isAllowedNavigation('javascript:alert(1)', ORIGIN));
  assert.ok(!isAllowedNavigation('pas une url', ORIGIN));
});

test('seuls les liens https s\'ouvrent dans le navigateur du système', () => {
  assert.ok(isExternalLink('https://osv.dev/vulnerability/GHSA-1'));
  assert.ok(!isExternalLink('http://example.test'));
  assert.ok(!isExternalLink('smb://serveur/partage'));
});

test('le backend n\'écoute que sur la boucle locale et s\'arrête avec l\'application', () => {
  const env = backendEnvironment({ port: 4000, dataDir: '/d', frontendDir: '/f', masterKey: 'k', cdxgenCommand: null });
  assert.equal(env.BIND_ADDRESS, '127.0.0.1');
  assert.equal(env.EXIT_ON_STDIN_CLOSE, 'true');
  assert.equal(env.MASTER_KEY, 'k');
  assert.equal(env.CDXGEN_COMMAND, undefined);
  assert.equal(env.ELECTRON_RUN_AS_NODE, undefined);
});

test('lanceurs cdxgen et atom : Electron comme Node.js, arguments rétablis, JRE embarqué', () => {
  const windows = launcherScripts({ electronPath: 'C:\\App\\Chiffrium.exe',
    shimPath: 'C:\\Data\\bin\\cdxgen-launch.mjs', atomShimPath: 'C:\\Data\\bin\\atom-launch.mjs', javaHome: 'C:\\App\\jre',
    windows: true });
  assert.ok(windows.cdxgen.includes('set ELECTRON_RUN_AS_NODE=1'));
  assert.ok(windows.cdxgen.includes('set ATOM_CMD=atom'));
  assert.ok(windows.cdxgen.includes('set "ATOM_JAVA_HOME=C:\\App\\jre"'));
  assert.ok(windows.cdxgen.includes('"C:\\App\\Chiffrium.exe" "C:\\Data\\bin\\cdxgen-launch.mjs" %*'));
  assert.ok(windows.atom.includes('"C:\\App\\Chiffrium.exe" "C:\\Data\\bin\\atom-launch.mjs" %*'));

  const linux = launcherScripts({ electronPath: '/opt/Crypto Analyzer/app', shimPath: "/home/it's/bin/cdxgen-launch.mjs",
    atomShimPath: null, javaHome: null, windows: false });
  assert.match(linux.cdxgen, /^#!\/bin\/sh/);
  assert.match(linux.cdxgen, /'\/opt\/Crypto Analyzer\/app'/);
  assert.ok(linux.cdxgen.includes(`'/home/it'\\''s/bin/cdxgen-launch.mjs' "$@"`));
  assert.equal(linux.atom, null);
  assert.doesNotMatch(linux.cdxgen, /ATOM_CMD/);

  // Sans la cale, yargs (sous Electron) prendrait le chemin du script pour le projet à analyser.
  const shim = shimScript(process.platform === 'win32' ? 'C:\\App\\cdxgen\\bin\\cdxgen.js' : '/app/cdxgen/bin/cdxgen.js');
  assert.ok(shim.includes('process.defaultApp = true;'));
  // Sans "windowsHide", cdxgen puis atom ouvrent une fenêtre console à chaque analyse.
  assert.ok(shim.includes('windowsHide: true'));
  const atomShim = atomShimScript(process.platform === 'win32'
    ? 'C:\\App\\atom\\index.js' : '/app/atom/index.js');
  assert.ok(atomShim.includes('windowsHide: true'));
  assert.ok(atomShim.includes('atom/index.js'));
  assert.match(shim, /await import\("file:\/\/\/(C:\/)?app\/cdxgen\/bin\/cdxgen\.js"\);/i);
});

test('un port libre est trouvé sur la boucle locale', async () => {
  const port = await freePort();
  assert.ok(Number.isInteger(port) && port > 0);
});

const { MODES, normalizeServerUrl, read, write } = require('../src/desktopConfig');

test('adresse du serveur d\'équipe : https obligatoire, sans identifiants', () => {
  assert.equal(normalizeServerUrl(' https://ca.example.test/chemin?x=1 '), 'https://ca.example.test');
  assert.equal(normalizeServerUrl('http://localhost:8080'), 'http://localhost:8080');
  assert.throws(() => normalizeServerUrl('http://ca.example.test'), /https/);
  assert.throws(() => normalizeServerUrl('https://user:pass@ca.example.test'), /identifiants/);
  assert.throws(() => normalizeServerUrl('pas une adresse'), /invalide/);
});

test('le mode choisi est mémorisé et relu', () => {
  const dir = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'ca-'));
  assert.equal(read(dir), null);
  write(dir, { mode: MODES.SERVER, serverUrl: 'https://ca.example.test/' });
  assert.deepEqual(read(dir), { mode: MODES.SERVER, serverUrl: 'https://ca.example.test' });
  write(dir, { mode: MODES.LOCAL });
  assert.deepEqual(read(dir), { mode: MODES.LOCAL });
});

test('seules l\'interface et l\'écran d\'accueil accèdent au pont (pas une page SSO tierce)', () => {
  assert.ok(isTrustedSender(`${ORIGIN}/#/analyses`, ORIGIN));
  assert.ok(isTrustedSender('file:///C:/Program%20Files/Chiffrium/resources/app.asar/src/welcome.html', null));
  assert.ok(!isTrustedSender('https://login.example.test/authorize', ORIGIN));
  assert.ok(!isTrustedSender('http://127.0.0.1:1/', ORIGIN));
  assert.ok(!isTrustedSender(undefined, ORIGIN));
});
