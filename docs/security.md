# Security


## Accounts and roles

There are three roles. A viewer reads their analyses and those of their groups, reads the catalog, downloads
files and can propose catalog changes. An analyst can also start, stop and delete their analyses. An
administrator has access to every analysis, to the catalog, to the accounts, to the settings and to the audit
log.

There is no default account. Creating the first administrator needs a random token written to
`data/secrets/setup-token` (and printed in the logs), destroyed afterwards. The desktop application supplies
it by itself in local mode.

A password is at least 12 characters long; common passwords and passwords containing the username are
refused (NIST SP 800-63B and ANSSI guidance: length matters more than complexity). Hashes use
PBKDF2-HMAC-SHA256 with 600,000 iterations and a 16-byte salt; the iteration count is stored with the hash,
which allows raising it later.

An account created by an administrator receives a temporary password, shown once; until it is changed, the
API answers `403 PASSWORD_CHANGE_REQUIRED` everywhere else.

Against brute force, an account is locked for 15 minutes after 5 failures, and an IP address is slowed down
after 20 failures in 5 minutes. An unknown username takes the same time to answer as a real one.

A session is a random 256-bit token of which only the hash is stored. It expires after a period of inactivity
and after a maximum lifetime, both configurable, and it is closed on password change, account deactivation
and password reset. The interface keeps it in `sessionStorage`: never in a URL and never in a cookie, so CSRF
is not possible.

You cannot disable yourself, nor remove the last active administrator.

### Lost administrator password

An administrator resets another account's password from Administration > Accounts. When no administrator can
sign in any more (sole administrator, no SSO), access is recovered outside the interface:

- desktop application in local mode: Help > Reset the administrator password (menu "Aide > Réinitialiser le
  mot de passe administrateur");
- server: `java -jar chiffrium-backend.jar reset-password <username>` (or `--sole-admin`), with the same
  `DATA_DIR`, database and `MASTER_KEY` as the server. The command asks to retype the username; `--yes` skips
  it (scripts), `--json` gives a machine-readable output.

The account receives a 16-character temporary password, shown once and to be changed at sign-in; its lock, if
any, is lifted and its sessions are closed. The action is written to the audit log (`USER_PASSWORD_RESET` and
`ADMIN_RECOVERY`, author `cli:<system user>@<host>`). The temporary password is only written to the command
output (or to the desktop application window), never to a log or to the audit; copied from the window, it is
cleared from the clipboard after one minute.

This recovery does not go through the network: it opens the database with the master key. Only someone who
already has access to the data can run it: the user's Windows session for the desktop application (the key is
protected there by the system keychain), access to the server and its master key otherwise. It is not an extra
access, since that person could already read the database; protecting the session (locking, disk encryption)
and the master key remains the condition of security. With the H2 database, the command refuses to run while
the application is open.

## Groups and visibility

An analysis without a group is private: only its author and the administrators see it. Shared with a group,
it is visible to its members. The managers of the group can stop it, rename it, change its visibility or
delete it, as its author can. An analysis invisible to someone answers "not found", without revealing that it
exists.

Joining a group is always consented to: an invitation must be accepted by the person invited, and a request
to join a public group must be accepted by a manager. Anyone can leave a group; the last manager must appoint
another one first.

A proposed catalog change is visible to its author, to the managers of their group and to the administrators.
Only an administrator approves it (the change is then applied and recorded) or rejects it with a reason.

## Single sign-on (OIDC)

The flow used is authorization code with PKCE S256. `state` and `nonce` are single-use and kept server-side.
The identity token is verified: signature against the key published by the provider (asymmetric algorithms
only), issuer, audience, expiry, nonce. The browser comes back with a ticket valid for 60 seconds and usable
once, exchanged for the session: the session token never travels in a URL.

The role is recomputed at each sign-in from the groups of the provider, when that is configured. A local
account with the same username is never linked to an SSO account, and the default role cannot be
administrator.

## Traceability

The audit log is append-only. It records sign-ins (successful, failed, lockouts), actions on accounts and
roles, analyses (start, result, stop, deletion, purge), file downloads, changes to the catalog, to the
settings (which sections changed, never the secrets), to the groups, and exports. Each entry carries the
SHA-256 hash of the previous one: a change or a deletion in the middle of the log shows up on verification.

To catch the deletion of the last entries as well, the log can be archived outside: to a folder
(`AUDIT_EXPORT_DIR`, ideally write-once) or to an https collector that receives HMAC-SHA256 signed
deliveries. Every hour the new entries are published and the last published entry is remembered. Retention
(six months minimum) only removes entries already archived and keeps a resume point, so that the chain stays
verifiable.

The source address is read from `X-Forwarded-For` only when `TRUST_PROXY=true`, and the nginx shipped with
the product overwrites that header.

## Protecting the data

The master key comes from `MASTER_KEY` (Kubernetes secret, vault) or, in the desktop application, from the
system keyring. Failing that, it sits in a file with restricted permissions. A sub-key is derived for each
use (HKDF). Losing that key makes all the data unreadable: it must be backed up separately.

- The H2 database (accounts, sessions, audit, settings) is encrypted, and every query is parameterised.
- Secrets in the settings (NVD key, SSO secret, alert webhook address) are encrypted and never returned by
  the API, which shows `********` instead.
- Reports, CBOMs, SARIF files and logs are encrypted at rest (AES-256-GCM) and decrypted on demand for the
  people allowed to see them. The same holds on S3 or on a shared folder.
- Git clones and raw cdxgen output are deleted at the end of every analysis, whether it succeeds, fails or is
  stopped. Leftovers are cleaned at start-up and every hour.
- Analyses older than the retention period, or beyond the quota, are purged every hour; each purge is
  recorded.
- A secret found in the code is redacted in the report (first four characters and length).

## Reducing the attack surface

No command goes through a shell: processes receive their arguments separately. cdxgen does not install the
dependencies of the analysed project, and npm is run with `--ignore-scripts` and a pinned registry.

Only HTTPS clones are accepted, optionally limited to a list of hosts; local folders must sit under an
allowed root; analysis identifiers are validated (UUID) to prevent path traversal.

Responses carry a strict CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` and
`no-store` on the API. The interface never uses `innerHTML`.

In the desktop application, the backend listens on `127.0.0.1` only. The window is isolated (`sandbox`,
`contextIsolation`), exposes no Node.js API and can only navigate to the application and to the SSO provider.
The bridge to the main process accepts the application interface and the welcome screen only, not a
third-party page. The engine reports its activity to the application only with a random token created at
each launch.


## Personal data (GDPR)

The organisation that deploys Chiffrium is the data controller. The tool processes the username, display name,
optional email address, role, groups, sign-in dates and IP address (audit log) of its users, and the analysed
code, which may contain names or email addresses.

- Legal basis: legitimate interest (information system security) and the security obligation of GDPR Article 32.
- Retention: analyses 90 days by default (configurable); audit log at least six months, purged only once
  archived.
- Rights: every user downloads their data from **My space**; an administrator can correct or disable an account.
  The audit log cannot be edited, as its security purpose allows (Article 17.3).
- Nothing is sent to the authors of Chiffrium, and there is no analytics.

In **Administration > Settings > Legal information**, fill in the organisation's name, the data protection
contact, and the notice shown on the sign-in page.
