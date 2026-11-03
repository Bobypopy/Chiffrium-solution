# Architecture


## Overview

The same backend and the same interface serve two contexts.

In server mode there are two containers. The frontend is an unprivileged nginx that serves the static files
and forwards `/api`; it keeps no state and can be replicated. The backend is a Java 21 application built on a
pinned cdxgen image.

In desktop mode, Electron starts the backend on `127.0.0.1` with a trimmed JRE and cdxgen, then displays the
interface served by that backend.

Data lives in `DATA_DIR`: an encrypted H2 database (accounts, sessions, audit, settings), the analyses and
their encrypted files, the catalog, a cache (the KEV catalog) and the secrets. Git clones are temporary and
deleted after each analysis; a report weighs a few hundred kB. Retention and quota bound the space used.
PostgreSQL replaces H2 for a team server.

## Backend

The backend follows a hexagonal architecture:

```
api (HTTP, Javalin) --> application (use cases) --> domain (business rules)
                              |
                              +-- ports (interfaces) <-- infrastructure (adapters)
```

- `domain` holds the model (assets, findings, verdicts, post-quantum readiness), the catalog, algorithm name
  normalisation, the policy, the score and security (roles, chained audit, password policy). It depends on
  the JDK only.
- `application` holds the analysis pipeline, the analysis queue, retention, authentication, groups,
  notifications and the ports.
- `infrastructure` implements those ports: cdxgen, JGit, rules, findings, key material, SARIF,
  OSV/KEV/EPSS/NVD, OIDC, H2 and PostgreSQL, S3, encryption, files.
- `api` exposes the REST routes.
- `Main` wires everything by hand, without an injection framework.

A few ports and their implementations:

| Port | Implementation |
|---|---|
| `SourceFetcher` | Git clone (JGit) or an allowed local folder |
| `SbomGenerator` | cdxgen |
| `CryptoDetector` | cdxgen, rule engine, key material, security findings |
| `VulnerabilityScanner` | OSV, enriched with KEV, EPSS and NVD |
| `IdentityProvider` | OpenID Connect |
| `AnalysisRepository` | encrypted files (single instance) or database + shared storage (several) |
| `JobQueue` | in-memory queue or shared database queue |
| `SecretCipher`, `PasswordHasher` | AES-256-GCM, PBKDF2 |

## How an analysis runs

An analysis chains: fetching the code, walking the files, preparation (npm lockfile for clones), cdxgen,
detections, policy evaluation, dependencies and vulnerabilities, graph, CBOM, report and SARIF export.
Finally, the files produced are encrypted.

Only fetching, walking, evaluation and the report are mandatory. If another step fails, the analysis carries
on and the report carries a warning. Inside each detector, a file that causes trouble is skipped and reported
without failing the step.

Every step is timed and logged into `analysis.log`, visible in the Steps & log tab.

An analysis can be stopped at any time. The thread running it is interrupted: the JGit clone stops, cdxgen
and its child processes are killed, and the check between two steps ends the pipeline. The analysis moves to
the "stopped" state. If the service itself stops (application closing, update, redeployment), the analysis
goes back into the queue and resumes at the next start-up.

## Design choices

- The policy, the detection rules, the finding rules and the TLS cipher suite table are JSON files: they
  change without touching the code.
- The clock is injected and the ports are easy to fake; the tests use real cdxgen output.
- Every external process and every network call has a time limit; file writes are atomic.
- Files are walked once per analysis; the constant index is built on demand; minified files are skipped.
- Bounded settings go through `AppConfig` (environment variables) or through the administration settings,
  which can be changed without a restart.
- The code runs on Windows and Linux; platform-specific paths and commands are kept in one place.

Security is covered in [security.md](security.md).

## Dependency inventory (cdxgen)

cdxgen lists the dependencies of every ecosystem and, through atom, follows data flows in Java and Python. It
produces no cryptographic inventory for the other languages, and its findings often lack a file and line: the
rule engine and the key material detector cover that. cdxgen is pinned (12.9.0 in `backend/Dockerfile`,
`docker-compose.yml` and `desktop/package.json`) and its readers are tested against real outputs
(`backend/src/test/resources/fixtures/cdxgen/`).

cdxgen never installs the analysed project's dependencies (`--no-install-deps`), and an allow list keeps it from
running the repository's own tools (`mvnw`, `gradlew`, `pipenv`...). Maven and Gradle dependencies are read by
Chiffrium directly from the build files.

## Desktop application

Electron ships the backend with a trimmed JRE (`jlink`), the web interface and cdxgen, run by Electron's own
Node.js. At start-up it picks a free port on `127.0.0.1`, starts the backend there, and keeps the master key in
the system keyring (DPAPI, libsecret or kwallet). Updates come from the releases of
this repository (https://github.com/Bobypopy/Chiffrium-solution/releases) through `electron-updater`, whose SHA-512
check protects the download.

## Several replicas

The mode is chosen with `ARTIFACT_STORE`.

With `local` (the default), a single instance runs. Analyses are encrypted files on the volume and the queue
is in memory.

With `s3` or `shared-dir` (PostgreSQL required), several instances share the work. The state of the analyses
is in the database (an encrypted document, with searchable columns in clear) and the files produced go,
encrypted, into S3-compatible object storage (MinIO, AWS, Scaleway...) or into a shared folder. The queue is
a table: an instance claims an analysis with `UPDATE ... WHERE status = 'QUEUED'`, which stops two instances
taking the same one. While running, the instance regularly signals that it is alive; if it disappears,
another marks the analysis as failed.

If the need grows, the next step would be to split the API from the workers (same image, role chosen by a
variable) and to size the number of workers to the length of the queue.

## REST API

Every route needs a session token (`Authorization: Bearer ...`), except `/api/health`, `/api/about` and the
sign-in routes. Errors look like `{ "error": "...", "code": "...", "details": [] }`.

| Path | Use |
|---|---|
| `/api/analyses` | list, start (POST) |
| `/api/analyses/{id}` | detail, deletion; `.../cancel`, `.../rerun`, `.../label`, `.../group` |
| `/api/analyses/{id}/report`, `cbom`, `sarif`, `log`, `bundle` | produced files |
| `/api/analyses/{id}/compare/{other}` | comparison of two analyses |
| `/api/catalog`, `/api/catalog/algorithms/{id}`, `/api/catalog/requests` | catalog and proposals |
| `/api/groups`, `/api/invitations/{id}/...`, `/api/me/...`, `/api/notifications` | groups, personal space |
| `/api/admin/...` | accounts, audit, settings, storage |
