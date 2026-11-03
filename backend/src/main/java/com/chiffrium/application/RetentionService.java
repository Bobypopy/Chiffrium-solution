package com.chiffrium.application;

import com.chiffrium.application.port.AnalysisRepository;
import com.chiffrium.application.settings.Settings;
import com.chiffrium.domain.model.AnalysisJob;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * Politique de conservation des données : purge des analyses trop anciennes puis, si le volume dépasse le
 * quota, des plus anciennes jusqu'à repasser sous la limite ; suppression des copies de travail orphelines
 * (clones Git). Chaque suppression d'analyse est tracée dans l'audit. Les analyses en cours ne sont jamais touchées.
 */
public final class RetentionService {

    private static final Logger LOG = LoggerFactory.getLogger(RetentionService.class);
    private static final long BYTES_PER_MB = 1024L * 1024L;

    private final AnalysisService analyses;
    private final AnalysisRepository repository;
    private final Supplier<Settings.Storage> storageSettings;
    private final Path workspaceRoot;
    private final Clock clock;

    /**
     * @param workspaceRoot dossier des copies de travail (clones Git, fichiers générés), une par analyse
     */
    public RetentionService(AnalysisService analyses, AnalysisRepository repository,
                            Supplier<Settings.Storage> storageSettings, Path workspaceRoot, Clock clock) {
        this.analyses = analyses;
        this.repository = repository;
        this.storageSettings = storageSettings;
        this.workspaceRoot = workspaceRoot;
        this.clock = clock;
    }

    /** Résultat d'une passe de purge. */
    public record Report(int purgedByAge, int purgedByQuota, long usedBytes, int workspacesCleaned,
                         long workspaceBytesFreed) {
    }

    /** Résultat d'un nettoyage des copies de travail. */
    public record Cleanup(int removed, long bytesFreed) {
    }

    /** Volume des copies de travail (clones Git en cours ou laissés par un arrêt brutal), en octets. */
    public long workspaceBytes() {
        return sizeOf(workspaceRoot);
    }

    /**
     * Supprime les copies de travail qui n'appartiennent à aucune analyse en cours sur cette instance : clones
     * laissés par un arrêt brutal, un plantage ou un fichier verrouillé au moment du nettoyage normal.
     */
    public synchronized Cleanup cleanWorkspaces() {
        if (!Files.isDirectory(workspaceRoot)) {
            return new Cleanup(0, 0);
        }
        Set<String> active = analyses.activeIds();
        int removed = 0;
        long freed = 0;
        try (Stream<Path> entries = Files.list(workspaceRoot)) {
            for (Path entry : entries.toList()) {
                if (active.contains(entry.getFileName().toString())) {
                    continue;
                }
                long size = sizeOf(entry);
                AnalysisPipeline.deleteQuietly(entry);
                if (!Files.exists(entry)) {
                    removed++;
                    freed += size;
                }
            }
        } catch (IOException e) {
            LOG.warn("Nettoyage des copies de travail incomplet", e);
        }
        if (removed > 0) {
            LOG.info("{} copie(s) de travail supprimée(s), {} Mo libéré(s)", removed, freed / BYTES_PER_MB);
        }
        return new Cleanup(removed, freed);
    }

    private static long sizeOf(Path root) {
        if (!Files.exists(root)) {
            return 0;
        }
        try (Stream<Path> files = Files.walk(root)) {
            return files.filter(Files::isRegularFile).mapToLong(f -> {
                try {
                    return Files.size(f);
                } catch (IOException e) {
                    return 0;
                }
            }).sum();
        } catch (IOException | UncheckedIOException e) {
            return 0;
        }
    }

    /** Volume occupé par les analyses, en octets. */
    public long usedBytes() {
        return repository.findAll().stream().mapToLong(job -> repository.sizeOf(job.id())).sum();
    }

    public synchronized Report apply() {
        Settings.Storage storage = storageSettings.get();
        List<AnalysisJob> finished = new ArrayList<>(repository.findAll().stream()
                .filter(job -> job.status().isTerminal())
                .toList());
        int byAge = 0;
        if (storage.retentionDays() > 0) {
            Instant limit = clock.instant().minus(Duration.ofDays(storage.retentionDays()));
            for (AnalysisJob job : List.copyOf(finished)) {
                if (job.createdAt().isBefore(limit)) {
                    analyses.purge(job.id(), "rétention de " + storage.retentionDays() + " jours dépassée");
                    finished.remove(job);
                    byAge++;
                }
            }
        }
        long used = usedBytes();
        int byQuota = 0;
        if (storage.maxStorageMb() > 0) {
            long quota = storage.maxStorageMb() * BYTES_PER_MB;
            // findAll trie du plus récent au plus ancien : on purge en partant de la fin.
            for (int i = finished.size() - 1; i >= 0 && used > quota; i--) {
                AnalysisJob job = finished.get(i);
                long size = repository.sizeOf(job.id());
                analyses.purge(job.id(), "quota de " + storage.maxStorageMb() + " Mo dépassé");
                used -= size;
                byQuota++;
            }
        }
        if (byAge + byQuota > 0) {
            LOG.info("Rétention : {} analyse(s) purgée(s) par ancienneté, {} par quota", byAge, byQuota);
        }
        Cleanup cleanup = cleanWorkspaces();
        return new Report(byAge, byQuota, used, cleanup.removed(), cleanup.bytesFreed());
    }
}
