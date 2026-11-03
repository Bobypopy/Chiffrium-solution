import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  catalogDiff, describeDiff, describePolicy,
  compareOids, filterCatalog, oidInfoUrl, quantumPosture, sortCatalog, suggestOids,
} from '../public/js/domain/catalog.js';
import {
  filterFindings, severityCounts, sortFindings, sortVulnerabilities,
} from '../public/js/domain/findings.js';

const findings = [
  { id: '1', severity: 'low', category: 'weak-random', title: 'Aléa', file: 'b.js', line: 3, ruleId: 'r1', testCode: false },
  { id: '2', severity: 'critical', category: 'secret', title: 'Jeton', file: 'a.java', line: 9, ruleId: 'r2', testCode: false },
  { id: '3', severity: 'high', category: 'secret', title: 'Clé', file: 'test/x.py', line: 1, ruleId: 'r3', testCode: true },
];

test('les constats les plus graves passent en premier', () => {
  assert.deepEqual(sortFindings(findings).map((f) => f.id), ['2', '3', '1']);
  assert.deepEqual(sortFindings(findings, 'file').map((f) => f.id), ['2', '1', '3']);
});

test('le filtre de gravité est un seuil minimal et le code de test peut être exclu', () => {
  assert.deepEqual(filterFindings(findings, { severity: 'high' }).map((f) => f.id), ['2', '3']);
  assert.deepEqual(filterFindings(findings, { includeTests: false }).map((f) => f.id), ['1', '2']);
  assert.deepEqual(filterFindings(findings, { category: 'secret', text: 'jeton' }).map((f) => f.id), ['2']);
});

test('répartition par gravité, du plus grave au moins grave', () => {
  assert.deepEqual(severityCounts(findings).map((r) => r.key), ['critical', 'high', 'low']);
});

test('vulnérabilités exploitées puis probabilité EPSS décroissante', () => {
  const sorted = sortVulnerabilities([
    { id: 'A', epss: 0.9 }, { id: 'B', knownExploited: true, epss: 0.01 }, { id: 'C' }, { id: 'D', epss: 0.2 },
  ]);
  assert.deepEqual(sorted.map((v) => v.id), ['B', 'A', 'D', 'C']);
});

const catalog = [
  { id: 'sha-256', name: 'SHA-256', primitive: 'hash', status: 'recommended', quantumVulnerable: false,
    aliases: ['sha256'], oids: [{ oid: '2.16.840.1.101.3.4.2.1' }] },
  { id: 'rsa', name: 'RSA', primitive: 'pke', status: 'acceptable', quantumVulnerable: true, aliases: ['rsa'],
    oids: [{ oid: '1.2.840.113549.1.1.1' }], disallowedAfter: 2035 },
  { id: 'md5', name: 'MD5', primitive: 'hash', status: 'disallowed', quantumVulnerable: false, aliases: ['md5'],
    oids: [{ oid: '1.2.840.113549.2.5' }] },
  { id: 'custom', name: 'Custom', primitive: 'other', status: 'unknown', quantumVulnerable: false, aliases: [], oids: [] },
];

test('les OID sont comparés arc par arc, numériquement', () => {
  assert.ok(compareOids('1.2.840.113549.1.1.1', '1.2.840.113549.2.5') < 0);
  assert.ok(compareOids('2.16.840', '1.2.840.113549') > 0);
  assert.ok(compareOids('1.2.10', '1.2.9') > 0);
  assert.ok(compareOids(null, '1.2') > 0);
});

test('tri du catalogue par OID, statut et dans les deux sens', () => {
  assert.deepEqual(sortCatalog(catalog, 'oid').map((a) => a.id), ['rsa', 'md5', 'sha-256', 'custom']);
  assert.deepEqual(sortCatalog(catalog, 'status').map((a) => a.id), ['sha-256', 'rsa', 'custom', 'md5']);
  assert.deepEqual(sortCatalog(catalog, 'name', 'desc').map((a) => a.id), ['sha-256', 'rsa', 'md5', 'custom']);
});

test('filtres du catalogue : texte (OID, alias), statut, résistance quantique', () => {
  assert.deepEqual(filterCatalog(catalog, { text: '113549.2' }).map((a) => a.id), ['md5']);
  assert.deepEqual(filterCatalog(catalog, { quantum: 'shor' }).map((a) => a.id), ['rsa']);
  assert.deepEqual(filterCatalog(catalog, { primitive: 'hash', status: 'disallowed' }).map((a) => a.id), ['md5']);
});

test('filtres du catalogue : type (protocole) et mots-clés de la note', () => {
  const entries = [
    { id: 'tls10', name: 'TLS 1.0', assetType: 'protocol', status: 'disallowed', note: 'RFC 8996' },
    { id: '3des', name: '3DES', status: 'disallowed', note: 'Blocs de 64 bits (attaque Sweet32)' },
  ];
  assert.deepEqual(filterCatalog(entries, { type: 'protocol' }).map((a) => a.id), ['tls10']);
  assert.deepEqual(filterCatalog(entries, { type: 'algorithm' }).map((a) => a.id), ['3des']);
  assert.deepEqual(filterCatalog(entries, { text: 'sweet32' }).map((a) => a.id), ['3des']);
});

test('proposition d\'OID à la saisie : identifiant, nom ou alias reconnus, jamais de choix ambigu', () => {
  const reference = [
    { id: 'hmac', name: 'HMAC', aliases: ['hmac'], oids: [{ oid: '1.2.840.113549.2.9', description: 'hmacWithSHA256' }] },
    { id: 'sha-256', name: 'SHA-256', aliases: ['sha256', 'sha2256'], oids: [{ oid: '2.16.840.1.101.3.4.2.1' }] },
    { id: 'sha-384', name: 'SHA-384', aliases: ['sha384'], oids: [{ oid: '2.16.840.1.101.3.4.2.2' }] },
  ];
  assert.equal(suggestOids(reference, { id: 'hmac' }).source.id, 'hmac');
  assert.equal(suggestOids(reference, { id: 'mon-sha', name: 'SHA 256' }).oids[0].oid, '2.16.840.1.101.3.4.2.1');
  assert.equal(suggestOids(reference, { id: 'x', name: 'Maison', aliases: ['sha2256'] }).source.id, 'sha-256');
  assert.equal(suggestOids(reference, { id: 'x', name: 'Algo maison' }), null);
  assert.equal(suggestOids(reference, { id: 'x', name: 'n', aliases: ['sha256', 'sha384'] }), null, 'ambigu');
  assert.equal(oidInfoUrl('1.2.840.113549.2.9'), 'https://oid-base.com/get/1.2.840.113549.2.9');
});

test('la posture quantique distingue "cassé par Shor", "post-quantique", "Grover" et "à proscrire"', () => {
  // RSA : cassé par Shor. SHA-256 : Grover seulement. MD5 : la question ne se pose plus. ML-KEM : conçu pour.
  assert.equal(quantumPosture({ primitive: 'pke', status: 'acceptable', quantumVulnerable: true }).id, 'shor');
  assert.equal(quantumPosture({ primitive: 'hash', status: 'recommended', quantumVulnerable: false }).id, 'grover');
  assert.equal(quantumPosture({ primitive: 'hash', status: 'disallowed', quantumVulnerable: false }).id, 'obsolete');
  assert.equal(quantumPosture({ primitive: 'kem', status: 'recommended', quantumVulnerable: false }).id, 'pqc');
  // SIKE est cassé classiquement : il ne doit surtout pas s'afficher "résistant".
  assert.equal(quantumPosture({ primitive: 'kem', status: 'disallowed', quantumVulnerable: false }).id, 'obsolete');
  // Un protocole générique dépend de ce qu'il négocie.
  assert.equal(quantumPosture({ primitive: 'other', status: 'acceptable', quantumVulnerable: false }).id, 'depends');
  assert.deepEqual(filterCatalog(catalog, { quantum: 'obsolete' }).map((a) => a.id), ['md5']);
});

test('écarts entre le catalogue en place et une politique importée', () => {
  const actuel = { algorithms: [{ id: 'aes', status: 'recommended' }, { id: 'des', status: 'disallowed' },
    { id: 'maison', status: 'acceptable' }] };
  const importe = { algorithms: [{ id: 'aes', status: 'recommended' }, { id: 'des', status: 'deprecated' },
    { id: 'ml-kem', status: 'recommended' }],
  policy: { name: 'Politique Groupe', version: 4, publishedBy: 'rssi', fingerprint: 'a1b2c3d4e5f60718' } };

  const diff = catalogDiff(actuel, importe);

  assert.deepEqual(diff.added, ['ml-kem']);
  // "maison" disparaîtrait : c'est exactement ce que l'utilisateur doit voir avant de valider.
  assert.deepEqual(diff.removed, ['maison']);
  assert.deepEqual(diff.changed, ['des']);
  assert.equal(diff.identical, false);
  assert.deepEqual(describeDiff(diff), ['1 ajout : ml-kem', '1 suppression : maison', '1 modification : des']);
  assert.equal(describePolicy(importe.policy),
    'Politique "Politique Groupe" version 4, publiée par rssi - empreinte a1b2c3d4e5f60718');

  assert.equal(catalogDiff(actuel, actuel).identical, true);
  assert.equal(describePolicy(null), null);
});
