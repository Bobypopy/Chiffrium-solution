# Detection rules

Detection is driven by JSON files: adding an API, an algorithm or a security check needs no Java code.

| What | Where |
|---|---|
| Rules that find algorithms and keys in code | `backend/src/main/resources/rules/*.json` (one pack per language) |
| Security findings (secrets, TLS, randomness...) | `backend/src/main/resources/findings/*.json` |
| Algorithm catalog (status, OIDs, quantum resistance) | `backend/src/main/resources/catalog/default-catalog.json` |
| Signatures in compiled code | `backend/src/main/resources/binary/signatures.json` |

## Coverage

| Area | Covered |
|---|---|
| Languages | Java, Kotlin, Scala, Groovy, Python, JavaScript/TypeScript, Go, C#, VB.NET, F#, C/C++, Objective-C, Swift, PHP, Ruby, Rust, Dart, Elixir, Erlang, Perl, Lua, R, Haskell, Solidity, Apex, ABAP, COBOL, PowerShell, SQL |
| Embedded code | `.vue`, `.svelte`, `.jsp`, `.cshtml`, `.razor`, `.erb`, Jupyter notebooks |
| Configuration | properties, YAML, JSON, Terraform/HCL, Bicep, ARM, CloudFormation, Helm, Ansible, Nix, `openssl.cnf`, IPsec, Android and iOS manifests |
| Scripts | OpenSSL, `ssh-keygen`, `keytool` and `gpg` commands in shell scripts, Dockerfiles, Makefiles and CI files |
| Compiled code | Java bytecode and archives, .NET assemblies, native libraries, Go and Rust binaries, `.pyc` |
| Key material | PEM, DER, PKCS#12, JKS, JWK, keys pasted in code |

## A rule pack

```json
{
  "id": "go",
  "languages": ["go"],
  "commentPrefixes": ["//", "/*", "*"],
  "functionPatterns": ["^\\s*func\\s+(?:\\([^)]*\\)\\s*)?(?<name>\\w+)\\s*[\\[(]"],
  "rules": [ ... ]
}
```

`functionPatterns` (and `classPatterns`) locate the enclosing function of each detection, shown as
`Class.method` and used to build the call graph.

Rules apply in order, and code already claimed by one rule is not offered to the next: put precise rules
before generic ones (`HMAC(EVP_sha1())` before `EVP_sha1()`).

## A rule

```json
{
  "id": "go.aes",
  "pattern": "\\baes\\s*\\.\\s*NewCipher\\s*\\(",
  "algorithm": "AES",
  "functions": ["encrypt", "decrypt"]
}
```

| Field | Purpose |
|---|---|
| `id` | unique identifier, shown in the report |
| `kind` | `algorithm` (default), `keysize`, `keybytes`, `mode`, `padding`, `curve` or `file` |
| `pattern` | Java regular expression; shorthands `{ARG}`, `{STR}`, `{FILE}`, `{SIZE}` |
| `algorithm`, `template`, `map` | fixed name, name template (`"HMAC-{name}"`) or name mapping |
| `functions`, `primitive` (and their `...ByApi` variants) | operations (`encrypt`, `sign`, `keygen`...) and primitive |
| `key`, `keyByApi` | the call creates a key: `private-key`, `secret-key` or `auto` |
| `skipUnrecognized`, `fallback` | ignore names missing from the catalog; drop a lone name already seen in a call |

Named groups: `algo` (an argument, resolved through constants, variables, parameters and calls across the
project), `name` (taken as is), `mode`, `padding`, `curve`, `size`, `bits`, `list`, `api`, `file`.

A `keysize`, `mode`, `padding` or `curve` rule completes the nearest detection above it in the same function:
`kpg.initialize(1024)` after `KeyPairGenerator.getInstance("RSA")` gives `RSA-1024`.

When an argument is not a literal, its value is traced back through assignments, fields, constructors and
calls, up to eight hops away. The path is shown in the report. A value that cannot be resolved produces an
"unresolved" asset to check by hand rather than nothing.

Keep expressions linear: every rule runs against lines of several hundred thousand characters in
`PathologicalInputTest`. For a quoted string, use `"[^"\\]*+(?:\\.[^"\\]*+)*+"`.

## Security findings

```json
{
  "id": "tls-python-verify-false",
  "category": "certificate-validation",
  "severity": "high",
  "cwe": "CWE-295",
  "languages": ["python"],
  "pattern": "\\bverify\\s*=\\s*False\\b",
  "title": "...", "description": "...", "recommendation": "..."
}
```

| Field | Purpose |
|---|---|
| `pattern` or `fileName` | expression on the content, or on the file name |
| `secretGroup`, `minEntropy` | the secret is redacted, low-entropy and placeholder values are skipped |
| `numberGroup`, `below` | raise when a number is too low (PBKDF2 iterations, bcrypt cost) |
| `listGroup`, `listCheck` | check a list of TLS cipher suites against `tls-cipher-suites.json` |
| `traceGroup`, `traceKind` | follow an argument (IV, salt, key, seed) back to where its value is written |
| `exclude`, `excludeFileName` | lines and files where the rule does not apply |

`findings/index.json` holds the shared settings: comment prefixes, test paths (their findings are lowered one
level), translation files (secret rules skip them), placeholder values, and the `chiffrium:ignore` marker.

## Catalog entries

An entry gives an algorithm its `status` (`recommended`, `acceptable`, `deprecated`, `disallowed`), whether it
is `quantumVulnerable`, transition years, key size rules, a `recommendation` and its `aliases`: compact
lowercase forms recognised in names (four characters or more anywhere, shorter ones as whole words).

An OID can be reserved for one use with `keySize`, `mode`, `padding`, `component` (the hash of a signature) or
`variant`; an asset gets the OID matching its exact use, or none if it is ambiguous:

```json
{ "oid": "2.16.840.1.101.3.4.1.46", "description": "id-aes256-GCM", "keySize": 256, "mode": "gcm" }
```

New default entries are merged into existing installations at start-up, without overwriting local changes.

## Testing

- Add a snippet and its expected assets to `RuleBasedCryptoDetectorTest` or `SecurityFindingDetectorTest`.
- The reference corpus (`backend/src/test/resources/reference`) holds a small project per language. Its exact
  result is compared with `expected.txt` on every build. After an intended change, regenerate it with
  `CHIFFRIUM_UPDATE_REFERENCE=1 mvn test -Dtest=ReferenceCorpusTest` and review the difference.
- `mvn test` also checks that every rule loads and that no alias is shared by two catalog entries.

French texts (titles, recommendations, catalog notes) need an English translation in
`frontend/public/js/i18n/data/`; a test fails otherwise.
