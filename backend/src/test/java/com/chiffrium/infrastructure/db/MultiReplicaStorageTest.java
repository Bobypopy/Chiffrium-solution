package com.chiffrium.infrastructure.db;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.AnalysisRepository.Artifact;
import com.chiffrium.application.port.ArtifactStore;
import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.model.AnalysisRequest;
import com.chiffrium.domain.model.AnalysisStatus;
import com.chiffrium.infrastructure.storage.FileArtifactStore;
import com.chiffrium.infrastructure.storage.S3ArtifactStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Serveur multi-répliques : file d'attente partagée en base (réservation exclusive, détection des répliques
 * arrêtées) et artefacts publiés dans un stockage partagé.
 */
class MultiReplicaStorageTest {

    private static final Instant NOW = Instant.parse("2026-05-01T10:00:00Z");
    private static final AnalysisRequest REQUEST = new AnalysisRequest("https://example.org/a.git", null, true, true,
            true, null);

    @TempDir
    Path dir;
    private Database database;

    @BeforeEach
    void open() {
        database = Database.h2(dir.resolve("db/test"), "cle-fichier-test", "cle-utilisateur-test");
    }

    @AfterEach
    void close() {
        database.close();
    }

    private JdbcAnalysisRepository repository(ArtifactStore store) {
        return new JdbcAnalysisRepository(database, TestSupport.MAPPER, TestSupport.cipher(), store,
                dir.resolve("work"));
    }

    @Test
    void anAnalysisIsClaimedByExactlyOneReplica() throws InterruptedException {
        JdbcAnalysisRepository repository = repository(new FileArtifactStore(dir.resolve("shared")));
        String id = UUID.randomUUID().toString();
        repository.save(AnalysisJob.queued(id, REQUEST, "alice", NOW));
        JdbcJobQueue first = new JdbcJobQueue(database, "replica-a", Clock.fixed(NOW, ZoneOffset.UTC));
        JdbcJobQueue second = new JdbcJobQueue(database, "replica-b", Clock.fixed(NOW, ZoneOffset.UTC));

        assertThat(first.pending()).isEqualTo(1);
        assertThat(first.take(Duration.ZERO)).contains(id);
        assertThat(second.take(Duration.ZERO)).as("déjà réservée").isEmpty();
        assertThat(second.pending()).isZero();

        repository.save(repository.find(id).orElseThrow().started(NOW));
        assertThat(repository.find(id)).get().extracting(AnalysisJob::status).isEqualTo(AnalysisStatus.RUNNING);

        JdbcJobQueue later = new JdbcJobQueue(database, "replica-b", Clock.fixed(NOW.plus(Duration.ofMinutes(10)),
                ZoneOffset.UTC));
        assertThat(later.abandoned(Duration.ofMinutes(5))).as("plus de signe de vie de replica-a").containsExactly(id);
        new JdbcJobQueue(database, "replica-a", Clock.fixed(NOW.plus(Duration.ofMinutes(9)), ZoneOffset.UTC))
                .heartbeat(id);
        assertThat(later.abandoned(Duration.ofMinutes(5))).isEmpty();
    }

    @Test
    void artifactsArePublishedEncryptedToTheSharedStore() throws Exception {
        Path shared = dir.resolve("shared");
        JdbcAnalysisRepository repository = repository(new FileArtifactStore(shared));
        String id = UUID.randomUUID().toString();
        repository.save(AnalysisJob.queued(id, REQUEST, "alice", "groupe-1", NOW));
        Path work = repository.artifactsDir(id);
        Files.writeString(work.resolve(Artifact.LOG.fileName()), "journal secret");
        Files.createDirectories(work.resolve("raw"));
        Files.writeString(work.resolve("raw/cdxgen.json"), "{}");

        assertThat(repository.readArtifact(id, Artifact.LOG)).as("lisible pendant l'exécution").isPresent();
        repository.seal(id, false);

        assertThat(work).doesNotExist();
        assertThat(repository.readArtifact(id, Artifact.LOG)).get()
                .extracting(bytes -> new String(bytes, StandardCharsets.UTF_8)).isEqualTo("journal secret");
        assertThat(Files.readAllBytes(shared.resolve(id).resolve(Artifact.LOG.fileName())))
                .as("chiffré au repos").isNotEqualTo("journal secret".getBytes(StandardCharsets.UTF_8));
        assertThat(shared.resolve(id).resolve("raw")).as("sorties brutes non conservées").doesNotExist();
        assertThat(repository.sizeOf(id)).isPositive();

        JdbcAnalysisRepository otherReplica = repository(new FileArtifactStore(shared));
        assertThat(otherReplica.find(id)).get().extracting(AnalysisJob::groupId).isEqualTo("groupe-1");
        assertThat(otherReplica.readArtifact(id, Artifact.LOG)).isPresent();

        otherReplica.delete(id);
        assertThat(repository.find(id)).isEmpty();
        assertThat(repository.readArtifact(id, Artifact.LOG)).isEmpty();
        assertThat(repository.findAll()).isEmpty();
    }

    /** Stockage objet réel : {@code docker run -p 9000:9000 minio/minio server /data}, puis TEST_S3_ENDPOINT=http://localhost:9000. */
    @Test
    @EnabledIfEnvironmentVariable(named = "TEST_S3_ENDPOINT", matches = "https?://.*")
    void s3CompatibleStorageRoundTrip() {
        S3ArtifactStore store = new S3ArtifactStore(new S3ArtifactStore.Config(
                URI.create(System.getenv("TEST_S3_ENDPOINT")), "us-east-1", "chiffrium-test",
                System.getenv().getOrDefault("TEST_S3_ACCESS_KEY", "minioadmin"),
                System.getenv().getOrDefault("TEST_S3_SECRET_KEY", "minioadmin")),
                Duration.ofSeconds(10), Clock.systemUTC()).ensureBucket();
        String prefix = UUID.randomUUID().toString();
        store.put(prefix + "/report.json", "{\"ok\":true}".getBytes(StandardCharsets.UTF_8));
        store.put(prefix + "/raw/a b.json", new byte[1024]);

        assertThat(store.get(prefix + "/report.json")).get()
                .extracting(bytes -> new String(bytes, StandardCharsets.UTF_8)).isEqualTo("{\"ok\":true}");
        assertThat(store.size(prefix)).isGreaterThanOrEqualTo(1024);
        store.deletePrefix(prefix);
        assertThat(store.get(prefix + "/report.json")).isEmpty();
        assertThat(store.size(prefix)).isZero();
    }
}
