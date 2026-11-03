package com.chiffrium.infrastructure.git;

import com.chiffrium.application.port.AnalysisException;
import com.chiffrium.domain.model.AnalysisRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GitSourceFetcherTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private static GitSourceFetcher fetcher(List<Path> localRoots, List<String> hosts) {
        return new GitSourceFetcher(localRoots, hosts, 1, TIMEOUT, "oauth2", Optional.empty());
    }

    private static AnalysisRequest request(String target) {
        return new AnalysisRequest(target, null, false, false, false, null);
    }

    @Test
    void rejectsNonHttpsUrlsAndEmbeddedCredentials() {
        GitSourceFetcher fetcher = fetcher(List.of(), List.of());
        assertThatThrownBy(() -> fetcher.validateUrl("http://gitlab.com/a/b.git"))
                .isInstanceOf(AnalysisException.class).hasMessageContaining("https");
        assertThatThrownBy(() -> fetcher.validateUrl("file:///etc/passwd")).isInstanceOf(AnalysisException.class);
        assertThatThrownBy(() -> fetcher.validateUrl("https://user:secret@gitlab.com/a/b.git"))
                .isInstanceOf(AnalysisException.class).hasMessageContaining("GIT_TOKEN");
        assertThat(fetcher.validateUrl("https://gitlab.com/a/b.git").getHost()).isEqualTo("gitlab.com");
    }

    @Test
    void enforcesHostAllowList() {
        GitSourceFetcher fetcher = fetcher(List.of(), List.of("gitlab.example.com"));
        assertThatThrownBy(() -> fetcher.validateUrl("https://github.com/a/b.git"))
                .isInstanceOf(AnalysisException.class).hasMessageContaining("non autorisé");
        assertThat(fetcher.validateUrl("https://GitLab.Example.Com/a/b.git")).isNotNull();
    }

    @Test
    void rejectsInvalidBranchNames(@TempDir Path workspace) {
        GitSourceFetcher fetcher = fetcher(List.of(), List.of());
        AnalysisRequest request = new AnalysisRequest("https://gitlab.com/a/b.git", "../../etc", false, false, false, null);
        assertThatThrownBy(() -> fetcher.fetch(request, workspace)).hasMessageContaining("branche");
    }

    @Test
    void localPathsMustBeUnderAnAllowedRoot(@TempDir Path root) throws Exception {
        Path allowed = Files.createDirectories(root.resolve("allowed/project"));
        Path forbidden = Files.createDirectories(root.resolve("forbidden"));
        GitSourceFetcher fetcher = fetcher(List.of(root.resolve("allowed")), List.of());

        assertThat(fetcher.resolveLocal(allowed.toString()).root()).isEqualTo(allowed.toRealPath());
        assertThatThrownBy(() -> fetcher.resolveLocal(forbidden.toString())).hasMessageContaining("hors des racines");
        assertThatThrownBy(() -> fetcher.resolveLocal(allowed.resolve("../../forbidden").toString()))
                .hasMessageContaining("hors des racines");
        assertThatThrownBy(() -> fetcher(List.of(), List.of()).resolveLocal(allowed.toString()))
                .hasMessageContaining("désactivée");
    }

    @Test
    void emptyTargetIsRejected(@TempDir Path workspace) {
        assertThatThrownBy(() -> fetcher(List.of(), List.of()).fetch(request("  "), workspace))
                .hasMessageContaining("obligatoire");
    }
}
