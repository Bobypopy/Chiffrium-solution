# Chiffrium

*[Version française](README.md)*

**Get your code ready for the post-quantum migration.**

Quantum computers will break RSA, elliptic curves and Diffie-Hellman. Before replacing those algorithms, you
need to know where they are. Chiffrium analyses a Git repository or a folder, finds all the cryptography it
uses, and tells you what will hold, what will not, and what to replace it with.

## What you get

- **A complete inventory**: algorithms, keys, certificates and protocols, in more than twenty languages,
  configuration files, infrastructure (Terraform, Kubernetes) and even compiled code.
- **A migration plan**: every use a quantum computer would break, its replacement (ML-KEM, ML-DSA, SLH-DSA) and
  the files to change, key exchanges first.
- **A standard CBOM** in CycloneDX 1.6 format, with the OID and NIST security level of every algorithm.
- **Common mistakes**: hardcoded secrets, disabled TLS verification, predictable randomness, fixed IVs.
- **Vulnerable dependencies**, ranked by real-world exploitation (CISA KEV, EPSS).

Every element is judged against a policy aligned with NIST, ANSSI and CNSA 2.0, which you can adapt. Your code
never leaves your machine or your server.

## Install

Download the [latest version](https://github.com/Bobypopy/Chiffrium-solution/releases/latest) for Windows or
Linux. Everything is included, nothing else to install.

For a team, Chiffrium also runs as a shared server (Docker or Kubernetes) that everyone reaches from the
application or a browser: see [docs/team-server.md](docs/team-server.md).

## Get started

1. Start Chiffrium, choose **On this machine** and create your administrator account.
2. Click **New analysis**, then paste a repository URL or pick a folder.
3. Open the report: the **Post-quantum migration** tab lists what has to change.

The [user guide](docs/guide.md) explains how to read a report.

## In continuous integration

The [GitHub Action](action/README.md) analyses the repository on every push and fails the
build when a disallowed algorithm appears. On other platforms, run the engine from the command line:

```bash
java -jar chiffrium-backend.jar analyze https://gitlab.com/group/project.git --fail-on disallowed --sarif out.sarif
```

## Documentation

| | |
|---|---|
| [User guide](docs/guide.md) | install, analyse, read the report, troubleshooting |
| [Team server](docs/team-server.md) | installation, configuration, backups |
| [Security](docs/security.md) | accounts, encryption, audit log, personal data |
| [Architecture](docs/architecture.md) | how it works inside, and the REST API |
| [Detection rules](docs/rules.md) | add an algorithm, an API or a rule |

## Contributing

Contributions are welcome, in English or French: read [CONTRIBUTING.md](CONTRIBUTING.md). To report a
vulnerability, use the repository's *Security* tab ([SECURITY.md](SECURITY.md)).

## Licence

Chiffrium is free software under the [AGPL-3.0](LICENSE). Copyright (C) 2025-2026 Bobypopy.

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org).
