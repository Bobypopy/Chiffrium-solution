# User guide

## Install

Download the installer from the [latest release](https://github.com/Bobypopy/Chiffrium-solution/releases/latest).

| System | File |
|---|---|
| Windows 10/11 | `Chiffrium-Setup-<version>.exe` |
| Debian, Ubuntu | `chiffrium-desktop_<version>_amd64.deb` (`sudo apt install ./chiffrium-desktop_*.deb`) |
| Any Linux | `Chiffrium-<version>.AppImage` (`chmod +x`, then run it) |

The application bundles Java and everything else it needs. On Windows, the installation takes a few minutes
because the antivirus scans each of its files.

If Windows shows *Windows protected your PC*, click *More info*: the publisher should read *SignPath
Foundation*. Then click *Run anyway*.

For a managed fleet, the Windows installer runs silently with `/S` (and `/D=<folder>` to choose where).

## Run your first analysis

1. Start Chiffrium and choose **On this machine**. The engine then listens on `127.0.0.1` only, and your data
   stays encrypted in your user profile. (**With my team** connects you to a [team server](team-server.md)
   instead.)
2. Create the administrator account. There is no default account.
3. Click **New analysis**, then paste the https URL of a Git repository or pick a folder on your disk.

Three options are worth knowing:

- **Dependency inventory** reads the project's dependency files (`pom.xml`, `package-lock.json`, `go.mod`...).
  No build tool is ever run.
- **Known vulnerabilities** sends library names and versions to the public OSV database, and to the package
  registries (PyPI, npm...) for the licences the dependency files do not give. Never any code. Untick it on an
  isolated machine.
- **Git history** also searches old commits for secrets that were deleted from the code but are still readable.
  The repository is then cloned in full, which is slower.

An ordinary project takes one to five minutes. You can stop an analysis at any time.

## Read the report

- **Dashboard**: a score out of 100 and, more useful, *What weighs most*: the algorithm families that cost the
  most points. Start there.
- **Assets**: every algorithm, key and certificate, with its status (recommended, acceptable, deprecated,
  disallowed), whether it withstands a quantum computer, and where it appears in the code. The detail of an
  asset shows its OID, its classical security in bits, and its NIST post-quantum category, from 1 (as strong as
  AES-128) to 5 (as strong as AES-256), or 0 if a quantum computer breaks it.
- **Post-quantum migration**: what a quantum computer would break, what to replace it with (ML-KEM for key
  exchange, ML-DSA or SLH-DSA for signatures) and where. Key exchanges come first, because data encrypted today
  can be recorded now and decrypted later.
- **Security findings**: hardcoded secrets, disabled TLS verification, predictable randomness, fixed IVs, weak
  key derivation. Secrets are redacted in the report.
- **Graph**: which functions use which algorithms.
- **Dependencies**: libraries, licences and known vulnerabilities, those exploited in the wild first.

To silence a false positive, add a `chiffrium:ignore` comment on the line. To change how an algorithm is
judged for your whole organisation, edit it in the **Catalog** (administrators), or propose the change (other
users).

**Compare with...** shows what appeared, disappeared or changed status between two analyses of the same
repository.

## Export

| Button | Use it for |
|---|---|
| CBOM (CycloneDX 1.6) | inventory tools and audits |
| SARIF | code review in GitHub, GitLab, Azure DevOps or SonarQube |
| Print / PDF | a security review or a committee |
| Full report (JSON), Download everything (ZIP) | automation and archiving |

## Your data

Your code never leaves the machine: it is read in a working folder that is deleted after the analysis. The
only outgoing requests are the ones you allow:

| Request | When | What is sent |
|---|---|---|
| Git clone | you analyse a remote repository | your request to that Git server |
| OSV, CISA KEV, EPSS, NVD | *Known vulnerabilities* is ticked | package names and versions, CVE identifiers |
| Package registries (PyPI, npm...) | *Known vulnerabilities* is ticked | package names and versions |
| Update check | at start-up, then every six hours | one request to github.com |

There is no telemetry. Reports and the database are encrypted (AES-256-GCM), and the master key is protected by
the system keyring.

| System | Data and log (`desktop.log`) |
|---|---|
| Windows | `%APPDATA%\Chiffrium\` |
| Linux | `~/.config/Chiffrium/` |

## Update and uninstall

The application checks for a new version at start-up and every six hours, and shows an **Update** button when it
is ready. If analyses are running, you choose whether to install now, when they finish, or on closing. The
`.deb` package is updated by installing the new one.

Uninstalling keeps your data, so that a reinstall loses nothing. To remove everything, delete the folder above.

## Troubleshooting

**The report lists no dependency.** Either *Dependency inventory* was unticked, or the project computes its
dependencies in a build script instead of declaring them. Algorithm detection works either way.

**"Repository unreachable".** Check the URL (https only), the network, and the access token for a private
repository. Behind a corporate proxy, see [team-server.md](team-server.md#configuration).

**An analysis is slow.** Cloning usually dominates. Untick the dependency inventory and the vulnerability
lookup for a quick first pass.

**Something went wrong.** Open an [issue](https://github.com/Bobypopy/Chiffrium-solution/issues) with
`desktop.log` attached: it holds the engine's errors, never your code.

## Before you analyse

Only analyse code you own or are allowed to analyse. The results support a review; they are not exhaustive, and
what is decided at runtime (a key fetched from a vault, a setting outside the repository) cannot be seen.
