// Prépare les ressources embarquées dans l'installateur :
//   resources/backend   : jar exécutable du backend (construit au préalable par Maven)
//   resources/frontend  : interface web statique
//   resources/jre       : environnement Java minimal produit par jlink (aucun Java requis sur le poste)
//   resources/license.txt : licence affichée par l'installateur
// Usage : JAVA_HOME=<JDK 21> node scripts/prepare.mjs

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const desktop = path.resolve(here, '..');
const root = path.resolve(desktop, '..');
const resources = path.join(desktop, 'resources');
const JAR_NAME = 'chiffrium-backend.jar';
const JAVA_RELEASE = '21';
/** Modules chargés dynamiquement, invisibles pour jdeps (TLS à courbes elliptiques, jeux de caractères...). */
const EXTRA_MODULES = ['jdk.crypto.ec', 'jdk.charsets', 'jdk.zipfs', 'jdk.net', 'jdk.management'];

function tool(name) {
  const javaHome = process.env.JAVA_HOME;
  if (!javaHome) throw new Error('JAVA_HOME doit désigner un JDK 21.');
  return path.join(javaHome, 'bin', process.platform === 'win32' ? `${name}.exe` : name);
}

function reset(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
}

const jar = path.join(root, 'backend', 'target', JAR_NAME);
if (!fs.existsSync(jar)) throw new Error(`Jar introuvable : ${jar} (lancer "mvn -f backend/pom.xml package").`);

reset(path.join(resources, 'backend'));
fs.copyFileSync(jar, path.join(resources, 'backend', JAR_NAME));

// L'installateur Windows (NSIS Unicode) lit le texte de licence en UTF-16 avec BOM : sans cela, les accents
// s'affichent mal : le "e" accentue de "Proprietaire" ressort en deux caracteres parasites.
const UTF16_BOM = Buffer.from([0xff, 0xfe]);
const license = fs.readFileSync(path.join(root, 'LICENSE'), 'utf8').replace(/\r?\n/g, '\r\n');
fs.writeFileSync(path.join(resources, 'license.txt'), Buffer.concat([UTF16_BOM, Buffer.from(license, 'utf16le')]));

// Version unique : la propriété Maven "revision" doit correspondre à desktop/package.json
// (la release surcharge les deux avec le numéro du tag).
const pom = fs.readFileSync(path.join(root, 'backend', 'pom.xml'), 'utf8');
const pomVersion = /<revision>([^<]+)<\/revision>/.exec(pom)?.[1];
const desktopVersion = JSON.parse(fs.readFileSync(path.join(desktop, 'package.json'), 'utf8')).version;
if (!process.env.APP_VERSION && pomVersion !== desktopVersion) {
  throw new Error(`Versions différentes : backend ${pomVersion}, application de bureau ${desktopVersion}.`);
}

reset(path.join(resources, 'frontend'));
fs.cpSync(path.join(root, 'frontend', 'public'), path.join(resources, 'frontend'), { recursive: true });

const moduleDeps = (jars) => execFileSync(tool('jdeps'), ['--ignore-missing-deps', '--multi-release', JAVA_RELEASE,
  '--print-module-deps', ...jars], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }).trim().split(',').filter(Boolean);
const detected = moduleDeps([jar]);
// atom (analyse de flux Java/Python lancée par cdxgen) s'exécute avec ce même JRE : ses modules sont ajoutés
// (sun.misc.Unsafe via jdk.unsupported, compilateur, JDI...), sinon il échoue avec NoClassDefFoundError.
const atomLib = path.join(desktop, 'node_modules', '@appthreat', 'atom', 'plugins', 'lib');
const atomJars = fs.existsSync(atomLib)
  ? fs.readdirSync(atomLib).filter((name) => name.endsWith('.jar')).map((name) => path.join(atomLib, name)) : [];
const atomModules = atomJars.length ? moduleDeps(atomJars) : [];
const modules = [...new Set([...detected, ...atomModules, ...EXTRA_MODULES])].sort();
const jre = path.join(resources, 'jre');
fs.rmSync(jre, { recursive: true, force: true });
execFileSync(tool('jlink'), ['--add-modules', modules.join(','), '--strip-debug', '--no-man-pages',
  '--no-header-files', '--compress=zip-6', '--output', jre], { stdio: 'inherit' });

console.log(`Ressources prêtes : ${modules.length} modules Java (${modules.join(', ')}).`);
