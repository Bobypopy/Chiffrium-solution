package com.chiffrium.infrastructure.config;

import com.chiffrium.domain.model.Language;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AppConfigTest {

    @Test
    void defaultsAreSafe() {
        AppConfig config = AppConfig.from(Map.of());
        assertThat(config.port()).isEqualTo(AppConfig.DEFAULT_PORT);
        assertThat(config.allowedLocalRoots()).isEmpty();
        assertThat(config.cdxgenInstallDeps()).isFalse();
        assertThat(config.cdxgenCryptoLanguages()).containsExactlyInAnyOrder(Language.JAVA, Language.PYTHON);
        assertThat(config.gitToken()).isEmpty();
        assertThat(config.osvEnabled()).isTrue();
    }

    @Test
    void readsAndBoundsValues() {
        AppConfig config = AppConfig.from(Map.of(
                "PORT", "9000",
                "CDXGEN_TIMEOUT_SECONDS", "120",
                "ALLOWED_GIT_HOSTS", "gitlab.com, github.com",
                "CDXGEN_CRYPTO_LANGUAGES", "java",
                "GIT_TOKEN", "secret-token"));
        assertThat(config.port()).isEqualTo(9000);
        assertThat(config.cdxgenDefaultTimeout()).isEqualTo(Duration.ofSeconds(120));
        assertThat(config.allowedGitHosts()).containsExactly("gitlab.com", "github.com");
        assertThat(config.toString()).doesNotContain("secret-token").contains("gitToken=***");
    }

    @Test
    void rejectsInvalidValues() {
        assertThatThrownBy(() -> AppConfig.from(Map.of("PORT", "abc"))).hasMessageContaining("PORT");
        assertThatThrownBy(() -> AppConfig.from(Map.of("MAX_CONCURRENT_ANALYSES", "0"))).hasMessageContaining("bornes");
        assertThatThrownBy(() -> AppConfig.from(Map.of("CDXGEN_CRYPTO_LANGUAGES", "klingon")))
                .hasMessageContaining("klingon");
    }

    @Test
    void multiReplicaStorageRequiresASharedDatabaseAndCompleteSettings() {
        assertThat(AppConfig.from(Map.of()).artifactStorage().distributed()).isFalse();
        assertThatThrownBy(() -> AppConfig.from(Map.of("ARTIFACT_STORE", "s3"))).hasMessageContaining("DATABASE_URL");
        assertThatThrownBy(() -> AppConfig.from(Map.of("ARTIFACT_STORE", "s3", "DATABASE_URL", "jdbc:postgresql://db/x")))
                .hasMessageContaining("S3_BUCKET");
        assertThatThrownBy(() -> AppConfig.from(Map.of("ARTIFACT_STORE", "ftp"))).hasMessageContaining("shared-dir");

        AppConfig.ArtifactStorage s3 = AppConfig.from(Map.of("ARTIFACT_STORE", "s3", "DATABASE_URL",
                "jdbc:postgresql://db/x", "S3_ENDPOINT", "http://minio:9000", "S3_BUCKET", "analyses",
                "S3_ACCESS_KEY", "id", "S3_SECRET_KEY", "secret-s3", "WORKER_ID", "pod-1")).artifactStorage();
        assertThat(s3.distributed()).isTrue();
        assertThat(s3.s3Region()).isEqualTo("us-east-1");
        assertThat(s3.toString()).contains("pod-1").doesNotContain("secret-s3");

        AppConfig.ArtifactStorage sharedDir = AppConfig.from(Map.of("ARTIFACT_STORE", "shared-dir", "DATABASE_URL",
                "jdbc:postgresql://db/x", "SHARED_ARTIFACTS_DIR", "partage")).artifactStorage();
        assertThat(sharedDir.mode()).isEqualTo(AppConfig.ArtifactStorage.Mode.SHARED_DIR);
        assertThat(sharedDir.sharedDir()).get().matches(p -> p.isAbsolute());
    }
}
