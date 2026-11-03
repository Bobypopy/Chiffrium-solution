import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  VIEWS, comparisonOrder, durationEstimate, filterJobs, groupSummary, groupView, queuePositions,
  sameTarget,
} from '../public/js/domain/jobs.js';

const job = (id, target, requestedBy, groupId, createdAt, status = 'succeeded') => ({
  id, request: { target }, requestedBy, groupId, createdAt, status,
});
const jobs = [
  job('1', 'https://git/a.git', 'alice', 'g1', '2026-01-01T00:00:00Z'),
  job('2', 'https://git/a.git', 'bob', null, '2026-02-01T00:00:00Z'),
  job('3', 'https://git/b.git', 'alice', 'g2', '2026-03-01T00:00:00Z', 'failed'),
];

test('vues : les miennes, favoris, groupe, recherche', () => {
  assert.deepEqual(filterJobs(jobs, { view: VIEWS.MINE, username: 'alice' }).map((j) => j.id), ['1', '3']);
  assert.deepEqual(filterJobs(jobs, { view: VIEWS.FAVORITES, favorites: new Set(['2']) }).map((j) => j.id), ['2']);
  assert.deepEqual(filterJobs(jobs, { view: groupView('g2') }).map((j) => j.id), ['3']);
  assert.deepEqual(filterJobs(jobs, { text: 'BOB' }).map((j) => j.id), ['2']);
});

test('comparaison : la plus ancienne sert de référence, candidates du même dépôt terminées', () => {
  assert.deepEqual(comparisonOrder(jobs[1], jobs[0]).map((j) => j.id), ['1', '2']);
  assert.deepEqual(sameTarget(jobs, jobs[0]).map((j) => j.id), ['2']);
  assert.deepEqual(sameTarget(jobs, jobs[2]), []);
});

test('position dans la file : par ordre de soumission, analyses en attente seulement', () => {
  const positions = queuePositions([
    { id: 'c', status: 'queued', createdAt: '2026-01-01T10:02:00Z' },
    { id: 'r', status: 'running', createdAt: '2026-01-01T09:00:00Z' },
    { id: 'a', status: 'queued', createdAt: '2026-01-01T10:00:00Z' },
  ]);
  assert.equal(positions.get('a'), 1);
  assert.equal(positions.get('c'), 2);
  assert.equal(positions.has('r'), false);
});

test('durée habituelle : mesurée sur le même dépôt, sinon sur toutes, et silencieuse sans recul', () => {
  const termine = (id, target, minutes) => ({ id, status: 'succeeded', request: { target },
    startedAt: '2026-01-01T10:00:00Z', finishedAt: new Date(Date.parse('2026-01-01T10:00:00Z')
      + minutes * 60_000).toISOString() });
  const encours = { id: 'x', status: 'running', request: { target: 'depot-a' },
    startedAt: '2026-01-02T10:00:00Z' };

  // Deux analyses seulement : pas assez pour annoncer une durée.
  assert.equal(durationEstimate([termine('1', 'depot-a', 2), termine('2', 'depot-a', 4)], encours), null);

  const historique = [termine('1', 'depot-a', 2), termine('2', 'depot-a', 3), termine('3', 'depot-a', 4),
    termine('4', 'depot-b', 30)];
  const estimation = durationEstimate(historique, encours);
  assert.equal(estimation.sameTarget, true);
  assert.equal(estimation.sample, 3);
  assert.equal(estimation.median, 3 * 60_000);
  // Le dépôt b, bien plus lent, ne pollue pas l'estimation du dépôt a.
  assert.ok(estimation.high < 5 * 60_000);

  // Dépôt jamais analysé : on se rabat sur l'ensemble des mesures.
  const nouveau = durationEstimate(historique, { id: 'y', status: 'running', request: { target: 'depot-c' } });
  assert.equal(nouveau.sameTarget, false);
  assert.equal(nouveau.sample, 4);

  // Une analyse en échec n'apprend rien sur la durée : elle n'est pas comptée.
  assert.equal(durationEstimate([...historique.slice(0, 2),
    { id: '9', status: 'failed', request: { target: 'depot-a' },
      startedAt: '2026-01-01T10:00:00Z', finishedAt: '2026-01-01T10:09:00Z' }], encours), null);
});

test('synthèse d\'un groupe : une seule analyse par dépôt, progression contre la précédente', () => {
  const analyse = (id, target, quand, score, interdits, quantique = 0) => ({
    id, status: 'succeeded', request: { target }, createdAt: quand, finishedAt: quand,
    summary: { score, byStatus: { disallowed: interdits, deprecated: 1 }, quantumVulnerable: quantique,
      vulnerabilities: 2, knownExploited: 1, findings: 3 },
  });
  const jobs = [
    analyse('a2', 'depot-a', '2026-03-01T10:00:00Z', 70, 1),
    analyse('a1', 'depot-a', '2026-02-01T10:00:00Z', 50, 4),
    analyse('b1', 'depot-b', '2026-02-15T10:00:00Z', 40, 6),
    { id: 'c1', status: 'running', request: { target: 'depot-c' }, createdAt: '2026-03-02T10:00:00Z' },
  ];

  const state = groupSummary(jobs);

  // Deux dépôts suivis, trois analyses terminées : un dépôt analysé deux fois ne compte qu'une fois.
  assert.equal(state.repositories, 2);
  assert.equal(state.analyses, 3);
  assert.equal(state.score, 55);
  assert.equal(state.disallowed, 7);
  assert.equal(state.deprecated, 2);
  assert.equal(state.knownExploited, 2);
  assert.equal(state.improved, 1);
  assert.equal(state.worsened, 0);
  // Le dépôt le plus exposé d'abord, avec l'écart depuis l'analyse précédente.
  assert.deepEqual(state.repositoriesByRisk.map((r) => [r.target, r.disallowed, r.delta]),
    [['depot-b', 6, null], ['depot-a', 1, 20]]);
  assert.equal(state.lastAnalysisAt, '2026-03-01T10:00:00Z');

  // Groupe sans analyse terminée : la vue doit pouvoir dire "rien à montrer" sans planter.
  assert.equal(groupSummary([]).repositories, 0);
  assert.equal(groupSummary([]).score, null);
});
