// Chaîne complète de l'application de bureau, avec le vrai moteur : installation, arrêt, Aide > Réinitialiser le
// mot de passe administrateur, redémarrage, connexion avec le mot de passe provisoire. Lancé quand CHIFFRIUM_JAR
// désigne le jar construit (et JAVA_HOME un JDK 21), comme dans le workflow de publication.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const { startBackend } = require('../src/backend');
const { resetSoleAdminPassword } = require('../src/passwordReset');

const JAR = process.env.CHIFFRIUM_JAR;
const JAVA_HOME = process.env.JAVA_HOME;
const FORGOTTEN = 'phrase oubliée du test';

/** Ressources disposées comme dans l'installateur : jre/, backend/chiffrium-backend.jar, frontend/. */
function resources(dir) {
  fs.mkdirSync(dir);
  fs.symlinkSync(JAVA_HOME, path.join(dir, 'jre'), 'junction');
  fs.mkdirSync(path.join(dir, 'backend'));
  fs.copyFileSync(JAR, path.join(dir, 'backend', 'chiffrium-backend.jar'));
  fs.mkdirSync(path.join(dir, 'frontend'));
  return dir;
}

async function post(url, body) {
  const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body) });
  return { status: response.status, body: await response.json().catch(() => null) };
}

test('le mot de passe administrateur oublié se réinitialise depuis l\'application de bureau',
  { skip: !JAR || !JAVA_HOME ? 'CHIFFRIUM_JAR et JAVA_HOME requis' : false, timeout: 240_000 }, async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'chiffrium-reset-'));
    const output = [];
    const log = (text) => output.push(text);
    const options = { resourcesDir: resources(path.join(root, 'resources')),
      dataDir: path.join(root, 'data'), masterKey: crypto.randomBytes(32).toString('base64'), cdxgenCommand: null, log };
    try {
      let backend = await startBackend(options);
      const setupToken = fs.readFileSync(path.join(options.dataDir, 'secrets', 'setup-token'), 'utf8').trim();
      const setup = await post(`${backend.url}/api/auth/setup`,
        { setupToken, username: 'admin', password: FORGOTTEN, displayName: 'Administrateur' });
      assert.equal(setup.status, 201);
      await backend.stop();

      const result = await resetSoleAdminPassword(options);
      assert.equal(result.username, 'admin');
      assert.ok(result.temporaryPassword.length >= 16);
      // Le journal de l'application ne garde que l'issue, jamais le mot de passe provisoire.
      assert.ok(!output.join('').includes(result.temporaryPassword));

      backend = await startBackend(options);
      try {
        assert.notEqual((await post(`${backend.url}/api/auth/login`,
          { username: 'admin', password: FORGOTTEN })).status, 200);
        const login = await post(`${backend.url}/api/auth/login`,
          { username: 'admin', password: result.temporaryPassword });
        assert.equal(login.status, 200);
        assert.equal(login.body.user.mustChangePassword, true);
      } finally {
        await backend.stop();
      }
    } finally {
      // Le lien vers le JDK est retiré seul d'abord : la suppression récursive ne doit jamais le suivre.
      fs.unlinkSync(path.join(options.resourcesDir, 'jre'));
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
