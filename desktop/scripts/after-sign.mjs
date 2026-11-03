// Installateur Windows signé par SignPath (voir docs/code-signing.md) : la signature modifie le fichier, donc
// l'empreinte SHA-512 et la blockmap calculées par electron-builder ne correspondent plus. Sans cette mise à
// jour, les applications installées refuseraient la mise à jour (empreinte différente) ou téléchargeraient des
// blocs faux en mode différentiel.
//
//   node scripts/after-sign.mjs <installateur signé> <dossier dist>
//
// Remplace l'installateur de dist par sa version signée, régénère sa blockmap et réécrit latest.yml.

import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { buildBlockMap } = require('app-builder-lib/out/targets/blockmap/blockmap');
const yaml = require('js-yaml');

/**
 * @param {string} signedFile installateur signé (même nom que celui de dist)
 * @param {string} distDir dossier de sortie d'electron-builder (contient latest.yml)
 * @returns {Promise<{ file: string, size: number, sha512: string }>}
 */
export async function applySignedInstaller(signedFile, distDir) {
  const name = path.basename(signedFile);
  const target = path.join(distDir, name);
  const latestFile = path.join(distDir, 'latest.yml');
  if (!fs.existsSync(target)) throw new Error(`Installateur absent de ${distDir} : ${name}`);
  if (!fs.existsSync(latestFile)) throw new Error(`latest.yml absent de ${distDir}`);
  const latest = yaml.load(fs.readFileSync(latestFile, 'utf8'));
  const entry = (latest.files ?? []).find((f) => f.url === name);
  if (!entry) throw new Error(`latest.yml ne décrit pas ${name}`);

  fs.copyFileSync(signedFile, target);
  // Même format que celui d'electron-builder pour les installateurs NSIS (blockmap compressée en gzip).
  const { size, sha512 } = await buildBlockMap(target, 'gzip', `${target}.blockmap`);
  entry.sha512 = sha512;
  entry.size = size;
  if (latest.path === name) latest.sha512 = sha512;
  fs.writeFileSync(latestFile, yaml.dump(latest, { lineWidth: -1 }));
  return { file: target, size, sha512 };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const [signed, dist] = process.argv.slice(2);
  if (!signed || !dist) {
    console.error('Usage : node scripts/after-sign.mjs <installateur signé> <dossier dist>');
    process.exit(2);
  }
  const result = await applySignedInstaller(signed, dist);
  console.log(`Installateur signé appliqué : ${path.basename(result.file)} (${result.size} octets)`);
}
