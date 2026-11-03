package com.chiffrium.infrastructure.persistence;

import com.chiffrium.application.port.AnalysisRepository;
import com.chiffrium.application.port.SecretCipher;
import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.model.AnalysisReport;
import com.chiffrium.infrastructure.crypto.SecureFiles;
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
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Stockage des analyses sur disque, <b>chiffré au repos</b> (AES-256-GCM, clé dérivée de la clé maîtresse) :
 * <pre>
 * analyses/&lt;id&gt;/analysis.json   état de l'analyse
 * analyses/&lt;id&gt;/report.json     rapport
 * analyses/&lt;id&gt;/report.sarif    export SARIF
 * analyses/&lt;id&gt;/cbom.json       CBOM CycloneDX
 * analyses/&lt;id&gt;/analysis.log    journal (en clair pendant l'analyse, chiffré ensuite)
 * analyses/&lt;id&gt;/raw/           sorties brutes de cdxgen (supprimées par défaut)
 * </pre>
 * Les fichiers en clair d'une version précédente restent lisibles (compatibilité ascendante).
 */
public final class FileSystemAnalysisRepository implements AnalysisRepository {

    private static final Logger LOG = LoggerFactory.getLogger(FileSystemAnalysisRepository.class);
    private static final String JOB_FILE = "analysis.json";
    private static final String RAW_DIR = "raw";
    /** Les identifiants sont des UUID : toute autre valeur est refusée (protection contre "../"). */
    private static final Pattern ID_PATTERN = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private final Path root;
    private final ObjectMapper mapper;
    private final SecretCipher cipher;

    public FileSystemAnalysisRepository(Path root, ObjectMapper mapper, SecretCipher cipher) {
        this.root = root;
        this.mapper = mapper;
        this.cipher = cipher;
        try {
            Files.createDirectories(root);
            SecureFiles.restrictToOwner(root);
        } catch (IOException e) {
            throw new UncheckedIOException("Impossible de créer " + root, e);
        }
    }

    public static boolean isValidId(String id) {
        return id != null && ID_PATTERN.matcher(id).matches();
    }

    @Override
    public void save(AnalysisJob job) {
        writeEncrypted(dir(job.id()).resolve(JOB_FILE), job);
    }

    @Override
    public Optional<AnalysisJob> find(String id) {
        if (!isValidId(id)) {
            return Optional.empty();
        }
        return readJob(dir(id).resolve(JOB_FILE));
    }

    @Override
    public List<AnalysisJob> findAll() {
        try (Stream<Path> dirs = Files.list(root)) {
            return dirs.filter(Files::isDirectory)
                    .filter(d -> isValidId(d.getFileName().toString()))
                    .map(d -> readJob(d.resolve(JOB_FILE)))
                    .flatMap(Optional::stream)
                    .sorted(Comparator.comparing(AnalysisJob::createdAt).reversed())
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException("Lecture impossible de " + root, e);
        }
    }

    @Override
    public void delete(String id) {
        deleteRecursively(dir(id));
    }

    @Override
    public void saveReport(AnalysisReport report) {
        writeEncrypted(dir(report.analysisId()).resolve(Artifact.REPORT.fileName()), report);
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
        if (!isValidId(id)) {
            return Optional.empty();
        }
        Path file = dir(id).resolve(artifact.fileName());
        if (!Files.isRegularFile(file)) {
            return Optional.empty();
        }
        try {
            byte[] bytes = Files.readAllBytes(file);
            return Optional.of(cipher.isEncrypted(bytes) ? cipher.decrypt(bytes) : bytes);
        } catch (IOException e) {
            throw new UncheckedIOException("Lecture impossible : " + file, e);
        }
    }

    @Override
    public Path artifactsDir(String id) {
        Path dir = dir(id);
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new UncheckedIOException("Impossible de créer " + dir, e);
        }
        return dir;
    }

    @Override
    public void seal(String id, boolean keepRawOutputs) {
        Path dir = dir(id);
        for (Artifact artifact : Artifact.values()) {
            encryptInPlace(dir.resolve(artifact.fileName()));
        }
        Path raw = dir.resolve(RAW_DIR);
        if (!Files.isDirectory(raw)) {
            return;
        }
        if (!keepRawOutputs) {
            deleteRecursively(raw);
            return;
        }
        try (Stream<Path> files = Files.walk(raw)) {
            files.filter(Files::isRegularFile).forEach(this::encryptInPlace);
        } catch (IOException e) {
            LOG.warn("Chiffrement incomplet des sorties brutes de {}", id, e);
        }
    }

    @Override
    public long sizeOf(String id) {
        Path dir = dir(id);
        if (!Files.exists(dir)) {
            return 0;
        }
        try (Stream<Path> files = Files.walk(dir)) {
            return files.filter(Files::isRegularFile).mapToLong(p -> p.toFile().length()).sum();
        } catch (IOException e) {
            return 0;
        }
    }

    private void encryptInPlace(Path file) {
        if (!Files.isRegularFile(file)) {
            return;
        }
        try {
            byte[] bytes = Files.readAllBytes(file);
            if (!cipher.isEncrypted(bytes)) {
                AtomicFiles.writeBytes(file, cipher.encrypt(bytes));
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Chiffrement impossible : " + file, e);
        }
    }

    private void writeEncrypted(Path file, Object value) {
        try {
            AtomicFiles.writeBytes(file, cipher.encrypt(mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(value)));
        } catch (IOException e) {
            throw new UncheckedIOException("Écriture impossible : " + file, e);
        }
    }

    private Path dir(String id) {
        if (!isValidId(id)) {
            throw new IllegalArgumentException("Identifiant d'analyse invalide : " + id);
        }
        return root.resolve(id);
    }

    private Optional<AnalysisJob> readJob(Path file) {
        if (!Files.isRegularFile(file)) {
            return Optional.empty();
        }
        try {
            byte[] bytes = Files.readAllBytes(file);
            return Optional.of(mapper.readValue(cipher.isEncrypted(bytes) ? cipher.decrypt(bytes) : bytes, AnalysisJob.class));
        } catch (IOException | IllegalStateException e) {
            LOG.warn("Fichier d'analyse illisible ignoré : {}", file, e);
            return Optional.empty();
        }
    }

    private static void deleteRecursively(Path dir) {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> paths = Files.walk(dir)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(path);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Suppression impossible : " + dir, e);
        }
    }
}
