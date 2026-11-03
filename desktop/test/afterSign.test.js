const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const { buildBlockMap } = require('app-builder-lib/out/targets/blockmap/blockmap');
const yaml = require('js-yaml');

test('l\'installateur signé remplace celui de dist, avec une empreinte et une blockmap à jour', async () => {
  const { applySignedInstaller } = await import('../scripts/after-sign.mjs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'chiffrium-sign-'));
  try {
    const dist = path.join(root, 'dist');
    const signedDir = path.join(root, 'signed');
    fs.mkdirSync(dist);
    fs.mkdirSync(signedDir);
    const name = 'Chiffrium-Setup-9.9.9.exe';
    const unsigned = crypto.randomBytes(300_000);
    fs.writeFileSync(path.join(dist, name), unsigned);
    // Ce qu'electron-builder produit avant la signature.
    const before = await buildBlockMap(path.join(dist, name), 'gzip', path.join(dist, `${name}.blockmap`));
    fs.writeFileSync(path.join(dist, 'latest.yml'), yaml.dump({
      version: '9.9.9', files: [{ url: name, sha512: before.sha512, size: before.size }], path: name,
      sha512: before.sha512, releaseDate: '2026-11-03T00:00:00.000Z',
    }));
    // La signature Authenticode ajoute une table de signature : le fichier change.
    fs.writeFileSync(path.join(signedDir, name), Buffer.concat([unsigned, crypto.randomBytes(8_000)]));

    await applySignedInstaller(path.join(signedDir, name), dist);

    const installer = fs.readFileSync(path.join(dist, name));
    const expected = crypto.createHash('sha512').update(installer).digest('base64');
    const latest = yaml.load(fs.readFileSync(path.join(dist, 'latest.yml'), 'utf8'));
    assert.equal(installer.length, 308_000);
    assert.equal(latest.files[0].sha512, expected);
    assert.equal(latest.files[0].size, 308_000);
    assert.equal(latest.sha512, expected);
    assert.equal(latest.version, '9.9.9');
    assert.notEqual(expected, before.sha512);
    // Blockmap régénérée : elle décrit le fichier signé.
    const blockmap = JSON.parse(require('node:zlib').gunzipSync(fs.readFileSync(path.join(dist, `${name}.blockmap`))));
    const total = blockmap.files[0].sizes.reduce((a, b) => a + b, 0);
    assert.equal(total, 308_000);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('un installateur que latest.yml ne décrit pas est refusé', async () => {
  const { applySignedInstaller } = await import('../scripts/after-sign.mjs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'chiffrium-sign-'));
  try {
    fs.writeFileSync(path.join(root, 'Autre.exe'), 'x');
    fs.writeFileSync(path.join(root, 'latest.yml'), yaml.dump({ version: '1.0.0', files: [], path: 'Chiffrium.exe' }));
    await assert.rejects(applySignedInstaller(path.join(root, 'Autre.exe'), root), /ne décrit pas Autre\.exe/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
