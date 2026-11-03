// cdxgen embarqué : exécuté par le moteur Node.js d'Electron (ELECTRON_RUN_AS_NODE), sans installation de
// Node.js sur le poste. Le backend attend une commande unique : on génère de petits lanceurs dans `bin/`.
//
// Deux pièges d'Electron utilisé comme Node.js :
//  - yargs (lecture des arguments de cdxgen) croit être dans une application empaquetée et ne retire que le
//    premier argument : le chemin du script devenait "le projet à analyser". La cale cdxgen-launch.mjs
//    corrige ce point avant de charger cdxgen ;
//  - atom (analyse de flux Java/Python) est lancé avec la commande `node` et Java 21 : on lui fournit un
//    lanceur `atom` qui réutilise Electron, et le JRE embarqué.
//
// Les deux cales imposent aussi `windowsHide` aux processus enfants : sans cela, cdxgen puis atom ouvraient
// des fenêtres console pendant chaque analyse (atom lance le JRE, d'où deux fenêtres par analyse).

const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const WINDOWS = process.platform === 'win32';
const SHIM = 'cdxgen-launch.mjs';
const ATOM_SHIM = 'atom-launch.mjs';

/** Lignes communes aux cales : aucun processus enfant ne doit ouvrir de fenêtre console sous Windows. */
const HIDE_WINDOWS = [
  "const processus = createRequire(import.meta.url)('node:child_process');",
  "for (const nom of ['spawn', 'spawnSync', 'exec', 'execFile', 'execFileSync', 'execSync']) {",
  '  const original = processus[nom];',
  '  processus[nom] = (...args) => {',
  "    const options = args.findIndex((a, i) => i > 0 && a !== null && typeof a === 'object' && !Array.isArray(a));",
  '    if (options > 0) args[options] = { ...args[options], windowsHide: true };',
  '    else if (args.length > 1 && Array.isArray(args[1])) args.splice(2, 0, { windowsHide: true });',
  '    else args.push({ windowsHide: true });',
  '    return original(...args);',
  '  };',
  '}',
];

/**
 * Cale ESM exécutée avant cdxgen : `process.defaultApp` rétablit la lecture normale des arguments (yargs se
 * croit sinon dans une application empaquetée), et les processus enfants n'ouvrent plus de fenêtre.
 */
function shimScript(cdxgenEntry) {
  return [
    '// Généré par Chiffrium : voir desktop/src/cdxgen.js.',
    "import { createRequire } from 'node:module';",
    '',
    'process.defaultApp = true;',
    '',
    ...HIDE_WINDOWS,
    '',
    `await import(${JSON.stringify(pathToFileURL(cdxgenEntry).href)});`,
    '',
  ].join('\n');
}

/** Cale ESM d'atom : il lance le JRE lui-même, d'où sa propre fenêtre console à masquer. */
function atomShimScript(atomEntry) {
  return [
    '// Généré par Chiffrium : voir desktop/src/cdxgen.js.',
    "import { createRequire } from 'node:module';",
    '',
    ...HIDE_WINDOWS,
    '',
    `await import(${JSON.stringify(pathToFileURL(atomEntry).href)});`,
    '',
  ].join('\n');
}

/**
 * Lanceurs pour la plateforme courante.
 * @returns {{ cdxgen: string, atom: string | null }} contenu des scripts (atom absent si non embarqué)
 */
function launcherScripts({ electronPath, shimPath, atomShimPath, javaHome, windows = WINDOWS }) {
  if (windows) {
    const cdxgen = ['@echo off', 'set ELECTRON_RUN_AS_NODE=1',
      // Le lanceur atom voisin est trouvé par son nom (cdxgen découpe ATOM_CMD sur les espaces).
      'set "PATH=%~dp0;%PATH%"',
      atomShimPath ? 'set ATOM_CMD=atom' : null,
      javaHome ? `set "ATOM_JAVA_HOME=${javaHome}"` : null,
      `"${electronPath}" "${shimPath}" %*`, ''].filter((line) => line !== null).join('\r\n');
    const atom = atomShimPath
      ? ['@echo off', 'set ELECTRON_RUN_AS_NODE=1', `"${electronPath}" "${atomShimPath}" %*`, ''].join('\r\n')
      : null;
    return { cdxgen, atom };
  }
  const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
  const cdxgen = ['#!/bin/sh', 'export ELECTRON_RUN_AS_NODE=1',
    'PATH="$(dirname "$0"):$PATH"; export PATH',
    atomShimPath ? 'export ATOM_CMD=atom' : null,
    javaHome ? `export ATOM_JAVA_HOME=${quote(javaHome)}` : null,
    `exec ${quote(electronPath)} ${quote(shimPath)} "$@"`, ''].filter((line) => line !== null).join('\n');
  const atom = atomShimPath
    ? ['#!/bin/sh', `ELECTRON_RUN_AS_NODE=1 exec ${quote(electronPath)} ${quote(atomShimPath)} "$@"`, ''].join('\n')
    : null;
  return { cdxgen, atom };
}

/** Dossier node_modules hors archive asar (voir asarUnpack). */
function modulesDir() {
  return path.join(__dirname, '..', 'node_modules').replace(`app.asar${path.sep}`, `app.asar.unpacked${path.sep}`);
}

/** Script déclaré dans le champ "bin" d'un paquet, ou null. */
function binEntry(packageDir, name) {
  try {
    // Chemin direct : le champ "exports" du paquet interdit require.resolve('.../package.json').
    const meta = JSON.parse(fs.readFileSync(path.join(packageDir, 'package.json'), 'utf8'));
    const bin = typeof meta.bin === 'string' ? meta.bin : meta.bin?.[name];
    const entry = bin ? path.join(packageDir, bin) : null;
    return entry && fs.existsSync(entry) ? entry : null;
  } catch {
    return null;
  }
}

/**
 * Écrit les lanceurs dans `binDir` et retourne le chemin de celui de cdxgen, ou null si cdxgen n'est pas
 * embarqué (le backend fonctionne alors sans SBOM : règles, constats et matériel restent analysés).
 * @param {string} [javaHome] JRE embarqué (Java 21), utilisé par atom
 */
function prepareCdxgenLauncher(binDir, javaHome = null, electronPath = process.execPath) {
  const cdxgenEntry = binEntry(path.join(modulesDir(), '@cyclonedx', 'cdxgen'), 'cdxgen');
  if (!cdxgenEntry) return null;
  const atomEntry = binEntry(path.join(modulesDir(), '@appthreat', 'atom'), 'atom');
  fs.mkdirSync(binDir, { recursive: true });
  const shimPath = path.join(binDir, SHIM);
  fs.writeFileSync(shimPath, shimScript(cdxgenEntry));
  let atomShimPath = null;
  if (atomEntry) {
    atomShimPath = path.join(binDir, ATOM_SHIM);
    fs.writeFileSync(atomShimPath, atomShimScript(atomEntry));
  }
  const scripts = launcherScripts({ electronPath, shimPath, atomShimPath,
    javaHome: javaHome && fs.existsSync(javaHome) ? javaHome : null });
  const extension = WINDOWS ? '.cmd' : '';
  const launcher = path.join(binDir, `cdxgen${extension}`);
  fs.writeFileSync(launcher, scripts.cdxgen, { mode: 0o700 });
  const atomLauncher = path.join(binDir, `atom${extension}`);
  if (scripts.atom) fs.writeFileSync(atomLauncher, scripts.atom, { mode: 0o700 });
  else fs.rmSync(atomLauncher, { force: true });
  return launcher;
}

module.exports = { launcherScripts, shimScript, atomShimScript, prepareCdxgenLauncher };
