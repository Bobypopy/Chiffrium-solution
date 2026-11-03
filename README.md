# Chiffrium

*[English version](README.en.md)*

**Préparez la migration post-quantique de votre code.**

Les ordinateurs quantiques casseront RSA, les courbes elliptiques et Diffie-Hellman. Avant de remplacer ces
algorithmes, il faut savoir où ils sont. Chiffrium analyse un dépôt Git ou un dossier, retrouve toute la
cryptographie qu'il utilise, et vous dit ce qui tiendra, ce qui ne tiendra pas, et par quoi le remplacer.

## Ce que vous obtenez

- **Un inventaire complet** : algorithmes, clés, certificats et protocoles, dans plus de vingt langages, les
  fichiers de configuration, l'infrastructure (Terraform, Kubernetes) et même le code compilé.
- **Un plan de migration** : chaque usage cassé par un ordinateur quantique, son remplaçant (ML-KEM, ML-DSA,
  SLH-DSA) et les fichiers à modifier, en commençant par les échanges de clés.
- **Un CBOM standard** au format CycloneDX 1.6, avec l'OID et le niveau de sécurité NIST de chaque algorithme.
- **Les erreurs courantes** : secrets écrits en dur, vérification TLS désactivée, aléa prévisible, IV fixe.
- **Les vulnérabilités des dépendances**, classées selon leur exploitation réelle (CISA KEV, EPSS).

Chaque élément est jugé selon une politique alignée sur le NIST, l'ANSSI et CNSA 2.0, que vous pouvez adapter.
Votre code ne quitte jamais votre machine ou votre serveur.

## Installer

Téléchargez la [dernière version](https://github.com/Bobypopy/Chiffrium-solution/releases/latest) pour
Windows ou Linux. Tout est inclus, rien d'autre à installer.

Pour une équipe, Chiffrium s'installe aussi comme serveur partagé (Docker ou Kubernetes), auquel chacun se
connecte depuis l'application ou un navigateur : voir [docs/team-server.md](docs/team-server.md).

## Démarrer

1. Lancez Chiffrium, choisissez **Sur ce poste** et créez votre compte administrateur.
2. Cliquez sur **Nouvelle analyse**, puis collez l'URL d'un dépôt ou choisissez un dossier.
3. Ouvrez le rapport : l'onglet **Migration post-quantique** donne la liste de ce qu'il faut changer.

Le [guide d'utilisation](docs/guide.md) explique comment lire un rapport.

## En intégration continue

L'[action GitHub](action/README.md) analyse le dépôt à chaque poussée et fait échouer la
construction si un algorithme interdit apparaît. Sur une autre plateforme, le moteur s'utilise en ligne de
commande :

```bash
java -jar chiffrium-backend.jar analyze https://gitlab.com/groupe/projet.git --fail-on disallowed --sarif out.sarif
```

## Documentation

La documentation détaillée est en anglais.

| | |
|---|---|
| [Guide d'utilisation](docs/guide.md) | installer, analyser, lire le rapport, dépannage |
| [Serveur d'équipe](docs/team-server.md) | installation, configuration, sauvegardes |
| [Sécurité](docs/security.md) | comptes, chiffrement, journal d'audit, données personnelles |
| [Architecture](docs/architecture.md) | fonctionnement interne et API REST |
| [Règles de détection](docs/rules.md) | ajouter un algorithme, une API ou une règle |

## Contribuer

Les contributions sont bienvenues, en français ou en anglais : lisez [CONTRIBUTING.md](CONTRIBUTING.md). Pour
signaler une faille, passez par l'onglet *Security* du dépôt ([SECURITY.md](SECURITY.md)).

## Licence

Chiffrium est un logiciel libre sous licence [AGPL-3.0](LICENSE). Copyright (C) 2025-2026 Bobypopy.

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org).
