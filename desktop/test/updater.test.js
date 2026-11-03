const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { test } = require('node:test');

const { createUpdateController, STATUS } = require('../src/updater');

function fakeUpdater() {
  const updater = new EventEmitter();
  updater.installed = null;
  updater.checkForUpdates = async () => updater.emit('checking-for-update');
  updater.quitAndInstall = (silent, relaunch) => { updater.installed = { silent, relaunch }; };
  return updater;
}

function fakeTimers() {
  const timers = { callback: null };
  timers.setInterval = (callback) => { timers.callback = callback; return 1; };
  timers.clearInterval = () => { timers.callback = null; };
  return timers;
}

test('suit le téléchargement puis propose l\'installation', async () => {
  const updater = fakeUpdater();
  const states = [];
  const controller = createUpdateController({ autoUpdater: updater, activity: async () => null,
    beforeInstall: async () => {}, onChange: (s) => states.push(s.status) });
  await controller.check();
  updater.emit('update-available', { version: '2.4.0' });
  updater.emit('download-progress', { percent: 42.4 });
  assert.equal(controller.state().percent, 42);
  updater.emit('update-downloaded', { version: '2.4.0' });
  assert.equal(controller.state().status, STATUS.READY);
  // Une vérification ultérieure en échec (hors ligne) ne masque pas la mise à jour prête.
  updater.emit('error', new Error('hors ligne'));
  assert.equal(controller.state().status, STATUS.READY);
  assert.deepEqual(states.slice(0, 3), [STATUS.CHECKING, STATUS.DOWNLOADING, STATUS.DOWNLOADING]);
});

test('installe tout de suite après l\'arrêt propre du moteur', async () => {
  const updater = fakeUpdater();
  const order = [];
  const controller = createUpdateController({ autoUpdater: updater, activity: async () => ({ running: 1, queued: 0 }),
    beforeInstall: async () => order.push('arrêt du moteur'), onChange: () => {} });
  updater.emit('update-downloaded', { version: '2.4.0' });
  await controller.install('now');
  order.push('installation');
  assert.deepEqual(order, ['arrêt du moteur', 'installation']);
  assert.deepEqual(updater.installed, { silent: false, relaunch: true });
});

test('attend la fin des analyses avant d\'installer', async () => {
  const updater = fakeUpdater();
  const timers = fakeTimers();
  let current = { running: 1, queued: 2 };
  const controller = createUpdateController({ autoUpdater: updater, activity: async () => current,
    beforeInstall: async () => {}, onChange: () => {}, timers });
  updater.emit('update-downloaded', { version: '2.4.0' });
  await controller.install('when-idle');
  assert.equal(updater.installed, null);
  assert.equal(controller.state().installWhenIdle, true);
  assert.deepEqual(controller.state().waitingFor, { running: 1, queued: 2 });

  current = { running: 0, queued: 1 };
  await timers.callback();
  assert.equal(updater.installed, null, 'une analyse attend encore');
  current = { running: 0, queued: 0 };
  await timers.callback();
  assert.deepEqual(updater.installed, { silent: false, relaunch: true });
});

test('sans analyse en cours, "à la fin des analyses" installe immédiatement ; annulation possible', async () => {
  const updater = fakeUpdater();
  const timers = fakeTimers();
  const controller = createUpdateController({ autoUpdater: updater, activity: async () => ({ running: 2, queued: 0 }),
    beforeInstall: async () => {}, onChange: () => {}, timers });
  updater.emit('update-downloaded', { version: '2.4.0' });
  await controller.install('when-idle');
  controller.cancelScheduled();
  assert.equal(timers.callback, null);
  assert.equal(controller.state().installWhenIdle, false);

  const idle = createUpdateController({ autoUpdater: fakeUpdater(), activity: async () => ({ running: 0, queued: 0 }),
    beforeInstall: async () => {}, onChange: () => {} });
  await assert.rejects(() => idle.install('now'), /Aucune mise à jour/);
});

test('désactivé sans source de mise à jour (construction locale)', async () => {
  const controller = createUpdateController({ activity: async () => null, beforeInstall: async () => {},
    onChange: () => {} });
  assert.equal(controller.state().status, STATUS.DISABLED);
  assert.equal((await controller.check()).status, STATUS.DISABLED);
});

// La 2.5.0 est restée en place alors que son correctif était téléchargé : electron-updater installait en
// silencieux à la fermeture, ce que notre installateur assisté refuse (il abandonne sans rien afficher).
test('n\'installe jamais en silencieux : l\'installateur assisté ne sait pas le faire', async () => {
  const updater = fakeUpdater();
  const controller = createUpdateController({ autoUpdater: updater, activity: async () => null,
    beforeInstall: async () => {}, onChange: () => {} });
  assert.equal(updater.autoInstallOnAppQuit, false, 'l\'installation silencieuse à la fermeture est désactivée');

  assert.equal(controller.isReady(), false, 'rien à installer tant que rien n\'est téléchargé');
  updater.emit('update-downloaded', { version: '2.5.2' });
  assert.equal(controller.isReady(), true, 'la fermeture doit alors lancer l\'installation');

  await controller.install('now');
  assert.deepEqual(updater.installed, { silent: false, relaunch: true }, 'installateur visible');
  assert.equal(controller.isReady(), false, 'une installation en cours ne se relance pas à la fermeture');
});
