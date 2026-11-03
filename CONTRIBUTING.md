# Contributing

Contributions are welcome, in English or French: detection rules, false-positive fixes, translations, code.
For anything large, open an issue first so we can agree on the approach.

## Build and run

You need JDK 21, Maven 3.9 and Node.js 20 or later. cdxgen (`npm i -g @cyclonedx/cdxgen@12.9.0`) is optional;
without it, everything but the dependency inventory works.

```bash
cd backend && mvn -q package -DskipTests
STATIC_DIR=../frontend/public java -jar target/chiffrium-backend.jar   # http://localhost:8080
```

The desktop application:

```bash
cd desktop && npm ci
JAVA_HOME=<JDK 21> node scripts/prepare.mjs   # copies the backend, the interface and a trimmed JRE
npm start
```

## Test

Run the three suites before opening a pull request:

```bash
cd backend && mvn verify
cd frontend && npm test
cd desktop && npm test
```

A new detection rule or a false-positive fix comes with a test that failed before the change. See
[docs/rules.md](docs/rules.md) for the rule format and the reference corpus.

## Conventions

- Follow the style of the surrounding code; avoid duplication.
- The interface is written in French and translated in `frontend/public/js/i18n/`: the French sentence is the
  key, the English translation goes into the table of its screen. Add the translation in the same change.
- Update the documentation the change affects.
- Keep commit messages to one line describing the change.
- Never commit tokens, passwords, certificates or reports of real repositories. Test fixtures use fake values.

## Contributor licence agreement

Chiffrium is licensed under the AGPL-3.0. To keep a commercial licence possible alongside it, every
contribution is made under the [CLA](CLA.md): you keep the copyright, and the project commits to keeping your
contribution available under an open-source licence. Tick the CLA box in the pull request template to accept it.

## Releases

Pushing a `vX.Y.Z` tag to a public repository builds the installers and publishes them in its releases
(`.github/workflows/release.yml`), where installed applications look for updates. To sign the Windows
installer, set the `SIGNPATH_*` variables and secret, or the `WINDOWS_CSC_*` secrets.
