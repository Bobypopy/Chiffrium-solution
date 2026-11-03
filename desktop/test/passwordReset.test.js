const assert = require('node:assert/strict');
const { test } = require('node:test');

const { failureMessage, parseResetOutput, resetEnvironment } = require('../src/passwordReset');

test('le mot de passe provisoire est lu dans la ligne JSON de la commande, journaux mis à part', () => {
  const output = [
    '10:12:01.123 INFO  Démarrage de Chiffrium 1.1.0',
    '{"username":"admin","temporaryPassword":"Xq7pR2mK9vLt4wZb"}',
    '',
  ].join('\r\n');
  assert.deepEqual(parseResetOutput(output), { username: 'admin', temporaryPassword: 'Xq7pR2mK9vLt4wZb' });
  assert.equal(parseResetOutput('{"autre": 1}\n{pas du json'), null);
});

test('en cas d\'échec, seul le message de la commande est montré', () => {
  const output = [
    '2026-11-01 10:12:01 INFO Démarrage',
    'Plusieurs administrateurs locaux : l\'un d\'eux peut réinitialiser ce mot de passe depuis Administration > Comptes.',
  ].join('\n');
  assert.match(failureMessage(output), /^Plusieurs administrateurs locaux/);
  assert.equal(failureMessage(''), 'la commande de réinitialisation a échoué');
  const trace = [
    'Exception in thread "main" java.lang.IllegalStateException: base illisible',
    '\tat com.chiffrium.Main.main(Main.java:129)',
    '\t... 3 more',
  ].join('\n');
  assert.match(failureMessage(trace), /base illisible/);
});

test('la commande reçoit les données et la clé du moteur local, sans les réglages propres au serveur', () => {
  const env = resetEnvironment({ dataDir: 'C:\\data', frontendDir: 'C:\\frontend', masterKey: 'clé' });
  assert.equal(env.DATA_DIR, 'C:\\data');
  assert.equal(env.MASTER_KEY, 'clé');
  // PORT=0 faisait refuser la configuration au démarrage de la commande (v1.1.0).
  assert.equal(env.PORT, undefined);
  assert.equal(env.EXIT_ON_STDIN_CLOSE, undefined);
});
