# Chiffrium GitHub Action

Analyses the repository on every push or pull request, publishes the results in the **Security** tab (code
scanning), and fails the job when a disallowed algorithm appears. It runs on the runner: your code is sent
nowhere.

```yaml
name: Cryptography
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # to publish the SARIF results

jobs:
  chiffrium:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: Bobypopy/Chiffrium-solution/action@v1.2.5
        id: chiffrium
      - uses: github/codeql-action/upload-sarif@v4
        if: always()           # publish the results even when the policy fails the job
        with:
          sarif_file: ${{ steps.chiffrium.outputs.sarif }}
```

| Input | Default | Purpose |
|---|---|---|
| `path` | `.` | folder to analyse |
| `fail-on` | `disallowed` | fail on a disallowed asset; `deprecated` is stricter; empty never fails |
| `sarif` | `chiffrium.sarif` | SARIF file produced (output `sarif`) |
| `history` | `false` | also search the Git history (needs `fetch-depth: 0` on checkout) |
| `vulnerabilities` | `false` | look up known vulnerabilities of the dependencies in OSV |
| `version` | the action's | Chiffrium version to download |

The action runs the rule engine only, without the dependency inventory: from a few seconds to a few minutes
depending on the size of the repository.
