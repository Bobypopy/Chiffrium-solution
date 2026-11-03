package com.chiffrium.infrastructure.git;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.HistoryScanner.HistoryResult;
import com.chiffrium.domain.model.SecurityFinding;
import com.chiffrium.infrastructure.findings.FindingRuleLoader;
import com.chiffrium.infrastructure.findings.SecurityFindingDetector;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.revwalk.RevCommit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GitHistoryScannerTest {

    private static final SecurityFindingDetector DETECTOR =
            new SecurityFindingDetector(new FindingRuleLoader(TestSupport.MAPPER).loadBuiltIn());
    /** Jeton au format GitHub, fabriqué pour le test (aucune valeur réelle). */
    private static final String FAKE_GITHUB_TOKEN = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5";
    private static final String PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf\n"
            + "-----END RSA PRIVATE KEY-----\n";

    private static RevCommit commit(Git git, String message) throws Exception {
        git.add().addFilepattern(".").call();
        git.add().addFilepattern(".").setUpdate(true).call();
        return git.commit().setMessage(message).setAuthor("test", "test@example.org")
                .setCommitter("test", "test@example.org").setSign(false).call();
    }

    @Test
    void findsSecretsThatOnlyRemainInTheHistory(@TempDir Path repo) throws Exception {
        RevCommit leak;
        try (Git git = Git.init().setDirectory(repo.toFile()).call()) {
            TestSupport.write(repo, "config/app.properties", "db.password=Hx7kQ2mP9vLr\nserver.port=8080\n");
            TestSupport.write(repo, "keys/deploy.pem", PEM);
            TestSupport.write(repo, "src/App.java", "class App { String t = \"" + FAKE_GITHUB_TOKEN + "\"; }\n");
            TestSupport.write(repo, "src/Random.java", "class R { int token = new Random().nextInt(); }\n");
            leak = commit(git, "première version");
            TestSupport.write(repo, "config/app.properties", "db.password=${DB_PASSWORD}\nserver.port=8080\n");
            Files.delete(repo.resolve("keys/deploy.pem"));
            Files.delete(repo.resolve("src/Random.java"));
            TestSupport.write(repo, "node_modules/lib/leak.js", "const t = '" + FAKE_GITHUB_TOKEN + "';\n");
            commit(git, "secrets retirés");
        }

        HistoryResult result = new GitHistoryScanner(DETECTOR, 1_000_000).scan(repo);

        assertThat(result.findings()).extracting(SecurityFinding::ruleId, SecurityFinding::file)
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("secret-config-assignment", "config/app.properties"),
                        org.assertj.core.groups.Tuple.tuple("secret-private-key", "keys/deploy.pem"));
        // Le jeton encore présent dans le code actuel relève de l'analyse normale ; l'aléa faible et les
        // dossiers ignorés (node_modules) ne sont pas cherchés dans l'historique.
        assertThat(result.findings()).allSatisfy(f -> {
            assertThat(f.commit()).isEqualTo(leak.getName());
            assertThat(f.snippet() + " " + f.evidence()).doesNotContain("Hx7kQ2mP9vLr");
        });
        assertThat(result.warnings()).isEmpty();
    }

    @Test
    void subfolderPathsAreRelativeToTheAnalysedFolder(@TempDir Path repo) throws Exception {
        try (Git git = Git.init().setDirectory(repo.toFile()).call()) {
            TestSupport.write(repo, "services/api/app.properties", "api.secret=Zq8vR2pL9wXk\n");
            TestSupport.write(repo, "services/web/app.properties", "web.secret=Mn4tY7uI2oPq\n");
            commit(git, "secrets");
            TestSupport.write(repo, "services/api/app.properties", "api.secret=${API_SECRET}\n");
            TestSupport.write(repo, "services/web/app.properties", "web.secret=${WEB_SECRET}\n");
            commit(git, "variables");
        }

        List<SecurityFinding> findings = new GitHistoryScanner(DETECTOR, 1_000_000)
                .scan(repo.resolve("services/api")).findings();

        assertThat(findings).extracting(SecurityFinding::file).containsExactly("app.properties");
    }

    @Test
    void longHistoriesAreTruncatedWithAWarning(@TempDir Path repo) throws Exception {
        try (Git git = Git.init().setDirectory(repo.toFile()).call()) {
            for (int i = 0; i < 3; i++) {
                TestSupport.write(repo, "README.txt", "version " + i + "\n");
                commit(git, "version " + i);
            }
        }

        HistoryResult result = new GitHistoryScanner(DETECTOR, 1_000_000, 2).scan(repo);

        assertThat(result.warnings()).singleElement().asString().contains("tronqué");
    }

    /**
     * Un dossier sans historique propre ne fait pas échouer l'analyse. Selon l'endroit où il se trouve, c'est un
     * dossier hors dépôt (avertissement) ou un sous-dossier d'un dépôt dont l'historique ne le concerne pas.
     */
    @Test
    void aFolderWithoutHistoryGivesNoFinding(@TempDir Path folder) throws Exception {
        TestSupport.write(folder, "app.properties", "db.password=Hx7kQ2mP9vLr\n");

        HistoryResult result = new GitHistoryScanner(DETECTOR, 1_000_000).scan(folder);

        assertThat(result.findings()).isEmpty();
        assertThat(result.warnings()).allSatisfy(w -> assertThat(w).startsWith("Historique Git"));
    }
}
