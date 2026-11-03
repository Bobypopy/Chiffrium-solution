const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const { explainFailure, stopOrphan } = require('../src/orphan');

test('explique une base déjà ouverte par une autre instance', () => {
  const output = 'org.h2.mvstore.MVStoreException: The file is locked: C:/Users/x/chiffrium.mv.db';
  assert.match(explainFailure(output), /déjà utilisée/);
  assert.match(explainFailure('Base de données inaccessible ou clé maîtresse incorrecte'), /déchiffrée/);
  assert.equal(explainFailure('Exception quelconque'), null);
});

test('ignore un fichier PID absent, invalide ou désignant un autre programme', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orphan-'));
  const pidFile = path.join(dir, 'backend.pid');
  const logs = [];
  assert.equal(stopOrphan(pidFile, 'chiffrium-backend.jar', (m) => logs.push(m)), false);

  fs.writeFileSync(pidFile, 'pas-un-nombre');
  assert.equal(stopOrphan(pidFile, 'chiffrium-backend.jar', (m) => logs.push(m)), false);
  assert.equal(fs.existsSync(pidFile), false, 'fichier obsolète supprimé');

  // Le processus de test est vivant mais n'exécute pas le moteur : il ne doit surtout pas être arrêté.
  fs.writeFileSync(pidFile, String(process.pid));
  assert.equal(stopOrphan(pidFile, 'chiffrium-backend.jar', (m) => logs.push(m)), false);
  assert.deepEqual(logs, []);
  fs.rmSync(dir, { recursive: true, force: true });
});
