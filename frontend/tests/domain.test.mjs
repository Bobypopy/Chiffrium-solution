// Tests unitaires de la logique front (sans navigateur) : node --test
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { elapsed, formatDuration, parseTargets, plural, shortTarget } from '../public/js/domain/format.js';
import {
  describeNode, keyboardOrder, neighbourhood, neighboursOf, nodeForLocation, searchNodes, toGraphModel,
} from '../public/js/domain/graph.js';
import { statusInfo } from '../public/js/domain/labels.js';
import {
  assetQuantumPosture, distribution, facets, filterAssets, migrationPlan, occurrencesByFile, originOf, priorities,
  scoreBreakdown, scoreTone, sortAssets, statusDistribution,
} from '../public/js/domain/report.js';
import { clearPref, readPref, writePref } from '../public/js/ui/prefs.js';

const asset = (name, status, severity, extra = {}) => ({
  name, bomRef: `crypto/algorithm/${name}`, assetType: 'algorithm',
  algorithm: { primitive: extra.primitive ?? 'hash', rawName: name },
  verdict: { status, severity, quantumVulnerable: extra.quantum ?? false },
  occurrences: extra.occurrences ?? [{ file: 'A.java', line: 3, language: 'java' }],
  sources: ['rules'], functions: [],
});

const ASSETS = [
  asset('SHA-256', 'recommended', 'none'),
  asset('MD5', 'disallowed', 'high'),
  asset('RSA-2048', 'acceptable', 'low', { primitive: 'pke', quantum: true,
    occurrences: [{ file: 'b.py', line: 9, language: 'python', function: 'keys.gen' }] }),
  asset('SHA-1', 'deprecated', 'medium'),
];

test('shortTarget extrait le nom du dépôt', () => {
  assert.equal(shortTarget('https://gitlab.com/g/projet.git'), 'projet');
  assert.equal(shortTarget('C:\\code\\demo\\'), 'demo');
  assert.equal(shortTarget(null), '-');
});

test('parseTargets ignore vides, commentaires et doublons', () => {
  assert.deepEqual(parseTargets('a\n\n# commentaire\nb\na\r\n'), ['a', 'b']);
});

test('formatDuration et elapsed', () => {
  assert.equal(formatDuration(450), '450 ms');
  assert.equal(formatDuration(1500), '1.5 s');
  assert.equal(formatDuration(125000), '2 min 5 s');
  assert.equal(elapsed('2026-01-01T00:00:00Z', '2026-01-01T00:00:02Z'), 2000);
  assert.equal(elapsed(null), null);
  assert.equal(plural(2, 'actif'), '2 actifs');
});

test('chaque actif dit sa position face au quantique', () => {
  const known = (name, primitive, status, quantum = false) => ({ ...asset(name, status, 'none', { primitive, quantum }),
    algorithm: { primitive, rawName: name, catalogId: name.toLowerCase() } });
  assert.equal(assetQuantumPosture(known('RSA', 'pke', 'acceptable', true)).id, 'shor');
  assert.equal(assetQuantumPosture(known('ML-KEM', 'kem', 'recommended')).id, 'pqc');
  assert.equal(assetQuantumPosture(known('AES', 'block-cipher', 'recommended')).id, 'grover');
  assert.equal(assetQuantumPosture(asset('Inconnu', 'unknown', 'info')), null, 'algorithme non reconnu : rien affirmé');
});

test('le plan de migration met les échanges de clés devant les signatures', () => {
  const at = (n) => Array.from({ length: n }, (_, i) => ({ file: `f${i % 2}.java`, line: i + 1 }));
  const plan = migrationPlan([
    asset('ECDSA', 'acceptable', 'low', { primitive: 'signature', quantum: true, occurrences: at(9) }),
    asset('ECDH', 'acceptable', 'low', { primitive: 'key-agree', quantum: true, occurrences: at(1) }),
    asset('RSA', 'acceptable', 'low', { primitive: 'pke', quantum: true, occurrences: at(4) }),
    asset('AES-256-GCM', 'recommended', 'none', { primitive: 'ae' }),
  ]);
  assert.deepEqual(plan.map((p) => p.asset.name), ['RSA', 'ECDH', 'ECDSA']);
  assert.deepEqual(plan.map((p) => p.keyExchange), [true, true, false]);
  assert.equal(plan[0].files, 2);
});

test('le tri par défaut place les actifs les plus graves en premier', () => {
  assert.deepEqual(sortAssets(ASSETS).map((a) => a.name), ['MD5', 'SHA-1', 'RSA-2048', 'SHA-256']);
  assert.deepEqual(sortAssets(ASSETS, 'name').map((a) => a.name), ['MD5', 'RSA-2048', 'SHA-1', 'SHA-256']);
});

test('les filtres se combinent', () => {
  assert.deepEqual(filterAssets(ASSETS, { status: 'disallowed' }).map((a) => a.name), ['MD5']);
  assert.deepEqual(filterAssets(ASSETS, { quantumOnly: true }).map((a) => a.name), ['RSA-2048']);
  assert.deepEqual(filterAssets(ASSETS, { language: 'python' }).map((a) => a.name), ['RSA-2048']);
  assert.deepEqual(filterAssets(ASSETS, { text: 'keys.gen' }).map((a) => a.name), ['RSA-2048']);
  assert.deepEqual(facets(ASSETS), { primitives: ['hash', 'pke'], languages: ['java', 'python'] });
});

test('distributions et priorités', () => {
  const rows = statusDistribution({ byStatus: { disallowed: 1, recommended: 3 } });
  assert.deepEqual(rows.map((r) => r.key), ['recommended', 'disallowed']);
  assert.equal(rows[0].share, 0.75);
  assert.deepEqual(distribution({ a: 1, b: 5, c: 0 }).map((r) => r.key), ['b', 'a']);
  assert.deepEqual(priorities(ASSETS, 1).map((a) => a.name), ['MD5']);
});

test('scoreTone et statusInfo', () => {
  assert.equal(scoreTone(90), 'good');
  assert.equal(scoreTone(70), 'warning');
  assert.equal(scoreTone(10), 'critical');
  assert.equal(statusInfo('disallowed').label, 'Interdit');
  assert.equal(statusInfo('inexistant').id, 'unknown');
});

test('occurrencesByFile regroupe et trie par ligne', () => {
  const groups = occurrencesByFile({ occurrences: [{ file: 'a', line: 9 }, { file: 'b', line: 1 }, { file: 'a', line: 2 }] });
  assert.deepEqual(groups.map((g) => [g.file, g.occurrences.map((o) => o.line)]), [['a', [2, 9]], ['b', [1]]]);
});

test('le modèle de graphe colore les actifs par statut et garde le graphe entier', () => {
  const report = {
    assets: [ASSETS[1], ASSETS[0]],
    callGraph: {
      nodes: [
        { id: 'fn:A.run', label: 'A.run', kind: 'function', file: 'A.java', line: 3 },
        { id: 'asset:crypto/algorithm/MD5', label: 'MD5', kind: 'asset', assetRef: 'crypto/algorithm/MD5' },
        { id: 'api:Cipher.init', label: 'Cipher.init', kind: 'crypto_api' },
        { id: 'fn:B.other', label: 'B.other', kind: 'function' },
        { id: 'asset:crypto/algorithm/SHA-256', label: 'SHA-256', kind: 'asset', assetRef: 'crypto/algorithm/SHA-256' },
      ],
      edges: [
        { from: 'fn:A.run', to: 'asset:crypto/algorithm/MD5', kind: 'uses' },
        { from: 'fn:A.run', to: 'api:Cipher.init', kind: 'calls' },
        { from: 'fn:B.other', to: 'asset:crypto/algorithm/SHA-256', kind: 'uses' },
      ],
    },
  };
  const model = toGraphModel(report);
  assert.equal(model.nodes.find((n) => n.id === 'asset:crypto/algorithm/MD5').colorToken, '--status-critical');
  assert.equal(model.edges.find((e) => e.kind === 'calls').dashed, true);

  // Chercher un actif ne doit rien retirer : on veut justement voir ce qui l'entoure.
  assert.equal(model.nodes.length, 5);
  assert.equal(model.partial, false);

  // Seules les API externes peuvent être masquées, à la demande.
  const sansApi = toGraphModel(report, { hideApis: true });
  assert.ok(!sansApi.nodes.some((n) => n.kind === 'crypto_api'));
  assert.equal(sansApi.nodes.length, 4);
  assert.equal(neighbourhood('x', []).size, 1);
});

test('recherche dans le graphe, emplacement d\'un constat et vue partielle des gros graphes', () => {
  const report = {
    assets: [ASSETS[1], ASSETS[0]],
    callGraph: {
      nodes: [
        { id: 'fn:A.init', label: 'A.init', kind: 'function', file: 'src/A.java', line: 3 },
        { id: 'fn:A.encrypt', label: 'A.encrypt', kind: 'function', file: 'src/A.java', line: 20 },
        { id: 'asset:crypto/algorithm/MD5', label: 'MD5', kind: 'asset', assetRef: 'crypto/algorithm/MD5' },
        { id: 'asset:crypto/algorithm/SHA-256', label: 'SHA-256', kind: 'asset', assetRef: 'crypto/algorithm/SHA-256' },
        { id: 'fn:B.hash', label: 'B.hash', kind: 'function', file: 'src/B.java', line: 5 },
      ],
      edges: [
        { from: 'fn:A.encrypt', to: 'asset:crypto/algorithm/MD5', kind: 'uses' },
        { from: 'fn:B.hash', to: 'asset:crypto/algorithm/SHA-256', kind: 'uses' },
      ],
    },
  };
  assert.deepEqual(searchNodes(report, 'encrypt'), ['fn:A.encrypt']);
  assert.deepEqual(searchNodes(report, 'b.java'), ['fn:B.hash'], 'recherche aussi par fichier');
  assert.deepEqual(searchNodes(report, '  '), []);
  assert.equal(nodeForLocation(report, 'src/A.java', 25), 'fn:A.encrypt', 'fonction déclarée juste avant');
  assert.equal(nodeForLocation(report, 'src/A.java', 10), 'fn:A.init');
  assert.equal(nodeForLocation(report, 'A.java', 25), 'fn:A.encrypt', 'chemin partiel, un seul fichier candidat');
  const ambiguous = { callGraph: { nodes: [...report.callGraph.nodes,
    { id: 'fn:C.x', label: 'C.x', kind: 'function', file: 'test/A.java', line: 1 }], edges: [] } };
  assert.equal(nodeForLocation(ambiguous, 'A.java', 25), null, 'deux fichiers A.java : pas de choix hasardeux');
  assert.equal(nodeForLocation(report, 'src/Z.java', 1), null);

  // Un graphe qui tient à l'écran est rendu en entier, recherche ou pas.
  assert.equal(toGraphModel(report).nodes.length, 5);

  // Vue partielle : l'actif le plus risqué (MD5, interdit) et ses voisins passent en premier.
  const partial = toGraphModel(report, { limit: 2 });
  assert.deepEqual(partial.nodes.map((n) => n.id).sort(), ['asset:crypto/algorithm/MD5', 'fn:A.encrypt']);
  assert.equal(partial.total, 5);

  // Ce que l'on cherche doit figurer dans la vue partielle, même si ce n'est pas le plus risqué.
  const avecCible = toGraphModel(report, { limit: 2, include: ['fn:B.hash'] });
  assert.ok(avecCible.nodes.map((n) => n.id).includes('fn:B.hash'));
  assert.equal(avecCible.partial, true);
  assert.equal(neighbourhood(['a'], [{ from: 'a', to: 'b' }, { from: 'b', to: 'c' }], 1).size, 2, 'profondeur bornée');
});

test('un actif sans lien reste à sa place dans le graphe, jamais seul à l\'écran', () => {
  const report = {
    assets: [
      { bomRef: 'crypto/material/key', name: 'Clé RSA', assetType: 'material',
        occurrences: [{ file: 'src/Keys.java', line: 12 }], verdict: { status: 'unknown' } },
    ],
    callGraph: {
      nodes: [
        { id: 'asset:crypto/material/key', label: 'Clé RSA', kind: 'asset', assetRef: 'crypto/material/key' },
        { id: 'fn:Keys.load', label: 'Keys.load', kind: 'function', file: 'src/Keys.java', line: 8 },
        { id: 'fn:Keys.save', label: 'Keys.save', kind: 'function', file: 'src/Keys.java', line: 20 },
        { id: 'fn:Ailleurs.run', label: 'Ailleurs.run', kind: 'function', file: 'src/Autre.java', line: 3 },
      ],
      edges: [{ from: 'fn:Keys.load', to: 'fn:Keys.save', kind: 'calls' }],
    },
  };

  // L'actif sans lien est dans le graphe comme les autres : c'est la vue qui zoome dessus, pas le modèle
  // qui efface le reste.
  const complet = toGraphModel(report);
  assert.deepEqual(complet.nodes.map((n) => n.id).sort(),
    ['asset:crypto/material/key', 'fn:Ailleurs.run', 'fn:Keys.load', 'fn:Keys.save']);
  assert.equal(neighboursOf(complet, 'asset:crypto/material/key').length, 0,
    'aucun lien : l\'interface le dira, sans amputer le graphe');

  // Vue partielle : l'actif reste présent dès qu'on le demande, malgré son absence de liens.
  const partielle = toGraphModel(report, { limit: 2, include: ['asset:crypto/material/key'] });
  assert.ok(partielle.nodes.map((n) => n.id).includes('asset:crypto/material/key'));
});

test('scoreBreakdown dit ce qui pèse le plus, du plus lourd au plus léger', () => {
  const parts = scoreBreakdown(ASSETS);

  // Quatre actifs : un interdit coûte 25 pts, un déprécié 0,75 x 25, un acceptable quantique 0,3 x 25.
  assert.deepEqual(parts.map((p) => [p.key, p.count, p.points]),
    [['disallowed', 1, 25], ['deprecated', 1, 19], ['acceptable-quantum', 1, 8]]);
  // Un actif recommandé ne coûte rien : il n'apparaît pas.
  assert.ok(!parts.some((p) => p.key === 'recommended'));
  // La ligne mène au bon filtre d'actifs.
  assert.deepEqual(parts[2], { key: 'acceptable-quantum', status: 'acceptable', quantum: true, count: 1, points: 8,
    algorithms: [{ name: 'RSA-2048', count: 1 }] });
});

test('scoreBreakdown : rien à signaler sur un projet sain ou vide', () => {
  assert.deepEqual(scoreBreakdown([]), []);
  assert.deepEqual(scoreBreakdown([asset('SHA-256', 'recommended', 'none')]), []);
  // Un seul actif déprécié noyé dans 500 actifs sains coûte moins d'un demi-point : on ne l'annonce pas.
  const beaucoup = Array.from({ length: 500 }, (_, i) => asset(`H${i}`, 'recommended', 'none'));
  assert.deepEqual(scoreBreakdown([...beaucoup, asset('SHA-1', 'deprecated', 'medium')]), []);
});

test('scoreBreakdown regroupe les algorithmes les plus fréquents du groupe', () => {
  const parts = scoreBreakdown([asset('MD5', 'disallowed', 'high'), asset('MD5', 'disallowed', 'high'),
    asset('DES', 'disallowed', 'high')]);

  assert.equal(parts.length, 1);
  assert.deepEqual(parts[0].algorithms, [{ name: 'MD5', count: 2 }, { name: 'DES', count: 1 }]);
});

test('les préférences se relisent, et un stockage absent ne casse rien', () => {
  const filtres = { filters: { status: 'disallowed' }, sort: 'name' };

  // Sans localStorage (cas de node, du mode privé ou d'un quota plein) : valeur par défaut, aucune exception.
  assert.deepEqual(readPref('report-filters', 'a1', { filters: {} }), { filters: {} });
  writePref('report-filters', 'a1', filtres);
  clearPref('report-filters', 'a1');

  // Avec un stockage : aller-retour fidèle, puis effacement.
  globalThis.localStorage = {
    valeurs: new Map(),
    getItem(cle) { return this.valeurs.get(cle) ?? null; },
    setItem(cle, valeur) { this.valeurs.set(cle, String(valeur)); },
  };
  try {
    writePref('report-filters', 'a1', filtres);
    assert.deepEqual(readPref('report-filters', 'a1'), filtres);
    assert.equal(readPref('report-filters', 'inconnue', 'defaut'), 'defaut');
    clearPref('report-filters', 'a1');
    assert.equal(readPref('report-filters', 'a1'), null);
  } finally {
    delete globalThis.localStorage;
  }
});

test('le graphe se parcourt au clavier : ordre, voisins et description parlée', () => {
  const report = {
    assets: [ASSETS[1]],
    callGraph: {
      nodes: [
        { id: 'fn:A.run', label: 'A.run', kind: 'function', file: 'A.java', line: 3 },
        { id: 'asset:crypto/algorithm/MD5', label: 'MD5', kind: 'asset', assetRef: 'crypto/algorithm/MD5' },
        { id: 'api:Cipher.init', label: 'Cipher.init', kind: 'crypto_api' },
      ],
      edges: [
        { from: 'fn:A.run', to: 'asset:crypto/algorithm/MD5', kind: 'uses' },
        { from: 'fn:A.run', to: 'api:Cipher.init', kind: 'calls' },
      ],
    },
  };
  const model = toGraphModel(report);

  // Les actifs d'abord : c'est ce que l'on vient chercher dans ce graphe.
  assert.deepEqual(keyboardOrder(model).map((n) => n.label), ['MD5', 'Cipher.init', 'A.run']);
  assert.deepEqual(neighboursOf(model, 'asset:crypto/algorithm/MD5')
    .map((l) => [l.node.label, l.label, l.outgoing]), [['A.run', 'utilise', false]]);

  assert.equal(describeNode(model, 'fn:A.run', { position: 3, total: 3 }),
    '3 sur 3. A.run, fonction dans A.java:3. 2 liens : utilise MD5, appelle Cipher.init.');
  assert.equal(describeNode(model, 'asset:crypto/algorithm/MD5'),
    'MD5, actif cryptographique. 1 lien : A.run utilise ce nœud.');
  assert.equal(describeNode(model, 'inconnu'), '');
});

test('le code de test est reconnu dans chaque écosystème, comme par l\'analyse', () => {
  for (const file of ['src/test/java/A.java', 'pkg/x/y_test.go', 'src/app.spec.ts', 'lib/Crypto/SelfTest/test_CBC.py',
    'src/foo/test_bar.py', 'helper/config_test_helpers.go', 'api/test-fixtures/key.pem',
    'vectors/cryptography_vectors/x.pem', 'fuzz/client.c', 'src/main/java/CryptoTest.java', 'test.sql',
    'molecule/mysql_hardening/converge.yml']) {
    assert.equal(originOf(file), 'test', file);
  }
  for (const file of ['src/latest/app.py', 'attest/verify.go', 'lib/contest.rb', 'src/main/java/Testing.java']) {
    assert.equal(originOf(file), 'project', file);
  }
  assert.equal(originOf('node_modules/x/test/a.js'), 'dependency');
});
