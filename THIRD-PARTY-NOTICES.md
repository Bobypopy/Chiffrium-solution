# Third-party notices

Chiffrium is licensed under the GNU AGPL-3.0 ([LICENSE](LICENSE)). It ships the following components, each under
its own licence; their licence files are kept, unmodified, in the distributed packages (jar, `node_modules`,
JRE). The application's About page shows the same list.

| Component | Licence | Use |
|---|---|---|
| Javalin, Eclipse Jetty | Apache-2.0 | HTTP server |
| Jackson | Apache-2.0 | JSON |
| Eclipse JGit | BSD-3-Clause (EDL-1.0) | Git clones |
| H2 Database | MPL-2.0 | embedded encrypted database |
| PostgreSQL JDBC, HikariCP | BSD-2-Clause, Apache-2.0 | team server database |
| Nimbus JOSE + JWT | Apache-2.0 | OpenID Connect |
| SLF4J, Logback | MIT, LGPL-2.1 | logging |
| OpenJDK (bundled JRE) | GPL-2.0 with Classpath Exception | Java runtime |
| CycloneDX cdxgen | Apache-2.0 | dependency inventory |
| AppThreat atom | MIT | data-flow analysis used by cdxgen |
| vis-network | Apache-2.0 or MIT | graph |
| Electron, electron-updater | MIT | desktop application |

Components offered under several licences are used under the one compatible with the AGPL-3.0: Apache-2.0 for
Jetty, MPL-2.0 for H2 and LGPL-2.1 for Logback. The JRE and cdxgen are separate programs, shipped alongside
Chiffrium and run as separate processes.

## Data sources

| Source | Terms |
|---|---|
| NIST publications (SP 800-131A, IR 8547, FIPS 203/204/205) | public domain (US government) |
| OSV | licence of each source database (mostly CC-BY-4.0) |
| CISA KEV | public domain (CC0) |
| FIRST EPSS | free use with attribution to FIRST.org |
| NVD | *This product uses the NVD API but is not endorsed or certified by the NVD.* |
