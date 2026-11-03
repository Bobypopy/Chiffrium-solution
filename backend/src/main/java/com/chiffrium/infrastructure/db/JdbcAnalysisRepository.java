package com.chiffrium.infrastructure.db;

import com.chiffrium.application.port.AnalysisRepository;
import com.chiffrium.application.port.ArtifactStore;
import com.chiffrium.application.port.SecretCipher;
import com.chiffrium.domain.model.AnalysisIds;
import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.model.AnalysisReport;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Analyses du serveur d'équipe multi-répliques : état en base (document JSON chiffré, colonnes de recherche en
 * clair), artefacts dans un {@link ArtifactStore} partagé (S3/MinIO ou volume partagé). Le dossier de travail
 * local ne sert que pendant l'exécution ; il est publié puis effacé au scellement.
 */
public final class JdbcAnalysisRepository implements AnalysisRepository {

    private static final Logger LOG = LoggerFactory.getLogger(JdbcAnalysisRepository.class);
    private static final String COLUMNS = "id, requested_by, group_id, status, created_at, document";
    private static final String RAW_DIR = "raw";

    private final Jdbc jdbc;
    private final ObjectMapper mapper;
    private final SecretCipher cipher;
    private final ArtifactStore store;
    private final Path workRoot;

    public JdbcAnalysisRepository(Database database, ObjectMapper mapper, SecretCipher cipher, ArtifactStore store,
                                  Path workRoot) {
        this.jdbc = new Jdbc(database);
        this.mapper = mapper;
        this.cipher = cipher;
        this.store = store;
        this.workRoot = workRoot;
    }

    @Override
    public void save(AnalysisJob job) {
        require(job.id());
        jdbc.upsert("analyses", "id", COLUMNS, job.id(), job.requestedBy(), job.groupId(), job.status().name(),
                job.createdAt(), cipher.encrypt(json(job)));
    }

    @Override
    public Optional<AnalysisJob> find(String id) {
        if (!AnalysisIds.isValid(id)) {
            return Optional.empty();
        }
        return jdbc.queryOne("SELECT document FROM analyses WHERE id = ?", rs -> rs.getBytes(1), id).map(this::job);
    }

    @Override
    public List<AnalysisJob> findAll() {
        return jdbc.query("SELECT document FROM analyses ORDER BY created_at DESC", rs -> rs.getBytes(1)).stream()
                .map(this::job)
                .toList();
    }

    @Override
    public void delete(String id) {
        require(id);
        jdbc.update("DELETE FROM analyses WHERE id = ?", id);
        store.deletePrefix(id);
        deleteLocal(workRoot.resolve(id));
    }

    @Override
    public void saveReport(AnalysisReport report) {
        store.put(key(report.analysisId(), Artifact.REPORT.fileName()), cipher.encrypt(json(report)));
    }

    @Override
    public Optional<AnalysisReport> readReport(String id) {
        return readArtifact(id, Artifact.REPORT).map(bytes -> {
            try {
                return mapper.readValue(bytes, AnalysisReport.class);
            } catch (IOException e) {
                throw new UncheckedIOException("Rapport illisible : " + id, e);
            }
        });
    }

    @Override
    public Optional<byte[]> readArtifact(String id, Artifact artifact) {
        if (!AnalysisIds.isValid(id)) {
            return Optional.empty();
        }
        Optional<byte[]> stored = store.get(key(id, artifact.fileName()));
        if (stored.isEmpty()) {
            // Analyse en cours sur cette réplique : artefact encore dans le dossier de travail.
            Path local = workRoot.resolve(id).resolve(artifact.fileName());
            try {
                stored = Files.isRegularFile(local) ? Optional.of(Files.readAllBytes(local)) : Optional.empty();
            } catch (IOException e) {
                throw new UncheckedIOException("Lecture impossible : " + local, e);
            }
        }
        return stored.map(bytes -> cipher.isEncrypted(bytes) ? cipher.decrypt(bytes) : bytes);
    }

    @Override
    public Path artifactsDir(String id) {
        Path dir = workRoot.resolve(require(id));
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new UncheckedIOException("Impossible de créer " + dir, e);
        }
        return dir;
    }

    /** Chiffre et publie les artefacts du dossier de travail, puis l'efface. */
    @Override
    public void seal(String id, boolean keepRawOutputs) {
        Path dir = workRoot.resolve(require(id));
        if (!Files.isDirectory(dir)) {
            return;
        }
        try (Stream<Path> files = Files.walk(dir)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                String relative = dir.relativize(file).toString().replace('\\', '/');
                if (relative.startsWith(RAW_DIR + "/") && !keepRawOutputs) {
                    continue;
                }
                byte[] bytes = Files.readAllBytes(file);
                store.put(key(id, relative), cipher.isEncrypted(bytes) ? bytes : cipher.encrypt(bytes));
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Publication impossible des artefacts de " + id, e);
        }
        deleteLocal(dir);
    }

    @Override
    public long sizeOf(String id) {
        return AnalysisIds.isValid(id) ? store.size(id) : 0;
    }

    private static String key(String id, String name) {
        return require(id) + "/" + name;
    }

    private static String require(String id) {
        if (!AnalysisIds.isValid(id)) {
            throw new IllegalArgumentException("Identifiant d'analyse invalide : " + id);
        }
        return id;
    }

    private AnalysisJob job(byte[] document) {
        try {
            return mapper.readValue(cipher.decrypt(document), AnalysisJob.class);
        } catch (IOException e) {
            throw new UncheckedIOException("Analyse illisible", e);
        }
    }

    private byte[] json(Object value) {
        try {
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(value);
        } catch (IOException e) {
            throw new UncheckedIOException("Sérialisation impossible", e);
        }
    }

    private static void deleteLocal(Path dir) {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> paths = Files.walk(dir)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        } catch (IOException e) {
            LOG.warn("Dossier de travail non supprimé : {}", dir, e);
        }
    }
}
