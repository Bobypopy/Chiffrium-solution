# Team server

The desktop application is enough for one person. When several people need to share analyses, one
cryptographic policy and one audit log, install a Chiffrium server once. Everyone then connects with a browser,
or with the desktop application in **With my team** mode.

```text
 desktop app --+
 desktop app --+-- https --> TLS proxy --> frontend (nginx) --> backend --> PostgreSQL
 browser     --+                                                  |
                                                encrypted volume (reports, CBOMs)
```

## What a server adds

- **Accounts and roles** (viewer, analyst, administrator), or single sign-on through OpenID Connect (Entra ID,
  Keycloak, Okta...), with roles mapped from directory groups.
- **Groups**: an analysis shared with a group is visible to its members only. People join on invitation, or
  ask to join a public group.
- **One policy**: the server's algorithm catalog applies to every analysis. Members propose changes, an
  administrator accepts or rejects them.
- **Notifications** in the interface, and optionally in Slack, Mattermost, Teams, Discord or by email.
- **An audit log** that can be archived outside the server.

## Install with Docker Compose

```bash
export MASTER_KEY="$(openssl rand -base64 32)"        # keep it in a vault: without it, nothing can be read
export POSTGRES_PASSWORD="$(openssl rand -base64 24)"
export DATABASE_URL="jdbc:postgresql://postgres:5432/chiffrium"

docker compose --profile team up -d
docker compose logs backend | grep "Première installation"   # one-time token to create the administrator
```

Without the `team` profile and `DATABASE_URL`, the backend uses its embedded encrypted database, which is fine
for a small team on a single server.

To analyse folders from the host, put them in `./workspace/` (mounted read-only).

## Put it behind HTTPS

The desktop application refuses a server over plain `http://`. Put a TLS proxy in front of the frontend, for
example Caddy, which gets the certificate by itself:

```text
chiffrium.example.com {
    reverse_proxy frontend:8080
}
```

## Configuration

Infrastructure is configured through environment variables. Everything else (retention, sessions, SSO,
vulnerability sources, alerts, legal notice) is set in **Administration > Settings**, without a restart.

| Variable | Default | Purpose |
|---|---|---|
| `MASTER_KEY` | generated in `data/secrets` | master key (Base64, 32 bytes) |
| `DATABASE_URL`, `DATABASE_USER`, `DATABASE_PASSWORD` | embedded H2 | PostgreSQL, e.g. `jdbc:postgresql://host:5432/db?sslmode=verify-full` |
| `ALLOWED_GIT_HOSTS` | all | Git hosts users may analyse |
| `ALLOWED_LOCAL_ROOTS` | none | local folders users may analyse |
| `GIT_TOKEN`, `GIT_USERNAME` | | access to private repositories |
| `MAX_CONCURRENT_ANALYSES`, `MAX_QUEUED_ANALYSES` | `2`, `20` | analysis queue |
| `CDXGEN_TIMEOUT_SECONDS` | `900` | time limit of the dependency inventory |
| `OSV_ENABLED` | `true` | known-vulnerability lookup |
| `AUDIT_EXPORT_DIR` | | folder where the audit log is archived |
| `TRUST_PROXY` | `false` | read the client address from `X-Forwarded-For` |
| `ARTIFACT_STORE` | `local` | `shared-dir` or `s3` to run several instances |
| `SHARED_ARTIFACTS_DIR` | | shared folder (NFS, SMB, Kubernetes RWX volume) |
| `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY` | region `us-east-1` | S3-compatible storage (MinIO, AWS, Scaleway...) |
| `PORT`, `DATA_DIR`, `LOG_LEVEL` | `8080`, `./data`, `INFO` | listening port, data folder, log level |

Behind a corporate proxy, set `JAVA_TOOL_OPTIONS="-Dhttps.proxyHost=... -Dhttps.proxyPort=..."` and
`HTTPS_PROXY`.

## Kubernetes

Kustomize manifests are in `deploy/k8s`:

```bash
kubectl apply -k deploy/k8s/overlays/local
kubectl -n chiffrium create secret generic backend-secrets \
  --from-literal=MASTER_KEY="$(openssl rand -base64 32)"
```

In production, expose the `frontend` service through an Ingress with cert-manager.

## Run several instances

With `ARTIFACT_STORE=s3` or `shared-dir` (PostgreSQL required), several backend instances share the work: the
analysis queue lives in the database, so two instances never run the same analysis, and reports go to the
shared storage. If an instance dies mid-analysis, another one marks it as failed after ten minutes.

MinIO gives you free, self-hosted object storage:

```bash
export MINIO_ROOT_PASSWORD="$(openssl rand -hex 24)" ARTIFACT_STORE=s3
docker compose --profile team --profile minio up -d --scale backend=2
```

Two cores and 4 GB of memory per instance are enough for a team running a few analyses a day.

## Move a desktop installation to the server

`migrate-db` copies accounts, groups, analyses, catalog and audit log into an empty PostgreSQL database. The
source is left untouched.

```bash
java -jar chiffrium-backend.jar migrate-db \
  --to jdbc:postgresql://server:5432/chiffrium --user chiffrium --password '...'
```

Copy the data folder and the master key as well.

## Back up and update

Back up three things together: the database (`pg_dump`), the `/data` volume, and the master key.

To update, deploy the new image. Running analyses are put back in the queue and resume on the new version;
open browser pages offer to reload.

## Lost administrator password

When no administrator can sign in any more, run this on the server, with the same `DATA_DIR`, database and
`MASTER_KEY`:

```bash
java -jar chiffrium-backend.jar reset-password <username>
```

It prints a temporary password, to be changed at the next sign-in, and records the action in the audit log.
See [security.md](security.md#lost-administrator-password).
