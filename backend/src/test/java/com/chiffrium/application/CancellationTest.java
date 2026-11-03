package com.chiffrium.application;

import com.chiffrium.TestSupport;
import com.chiffrium.application.security.Actor;
import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.model.AnalysisRequest;
import com.chiffrium.domain.model.AnalysisStatus;
import com.chiffrium.infrastructure.config.AppConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Arrêt d'une analyse : en attente (immédiat) et en cours (cdxgen simulé, qui ne se termine jamais seul, doit être
 * tué et la copie de travail supprimée).
 */
class CancellationTest {

    private static final Duration WAIT = Duration.ofSeconds(30);
    private static final String PASSWORD = "Phrase secrete du test 42";

    @Test
    void runningAndQueuedAnalysesCanBeStopped(@TempDir Path dir) throws Exception {
        Path project = TestSupport.fixture("projects/java-crypto-package");
        Path marker = dir.resolve("cdxgen-started");
        var application = new com.chiffrium.MainAccess(AppConfig.from(Map.of(
                "DATA_DIR", dir.resolve("data").toString(),
                "ALLOWED_LOCAL_ROOTS", project.getParent().toString(),
                "OSV_ENABLED", "false",
                "MAX_CONCURRENT_ANALYSES", "1",
                "CDXGEN_COMMAND", slowCdxgen(dir, marker).toString())));
        try {
            Actor admin = application.admin(PASSWORD);
            AnalysisRequest request = new AnalysisRequest(project.toString(), null, false, true, false, null);
            List<AnalysisJob> jobs = application.analyses().submit(admin, List.of(request, request), null);
            String running = jobs.get(0).id();
            String queued = jobs.get(1).id();

            await(() -> Files.exists(marker), "cdxgen démarré");
            AnalysisJob stoppedWhileQueued = application.analyses().cancel(admin, queued);
            assertThat(stoppedWhileQueued.status()).isEqualTo(AnalysisStatus.CANCELLED);

            application.analyses().cancel(admin, running);
            AnalysisJob stopped = await(running, application, j -> j.status().isTerminal());
            assertThat(stopped.status()).isEqualTo(AnalysisStatus.CANCELLED);
            assertThat(stopped.error()).contains("arrêtée par admin");
            assertThat(stopped.steps()).extracting(s -> s.step()).contains("récupération", "parcours");
            assertThat(application.analyses().find(admin, queued)).get().extracting(AnalysisJob::status)
                    .isEqualTo(AnalysisStatus.CANCELLED);
            await(() -> !Files.exists(dir.resolve("data/workspace").resolve(running)), "copie de travail supprimée");

            // Le travailleur n'a pas été tué par l'interruption : une nouvelle analyse sans cdxgen aboutit.
            AnalysisRequest quick = new AnalysisRequest(project.toString(), null, false, false, false, null);
            String next = application.analyses().submit(admin, List.of(quick), null).get(0).id();
            AnalysisJob after = await(next, application, j -> j.status().isTerminal());
            assertThat(after.status()).as("erreur : %s", after.error()).isEqualTo(AnalysisStatus.SUCCEEDED);
            assertThat(application.audit().search(null, "ANALYSIS_CANCELLED", 10, 0)).hasSize(2);
        } finally {
            application.close();
        }
    }

    /** Fermeture de l'application ou mise à jour : l'analyse en cours reprendra au démarrage suivant. */
    @Test
    void shuttingDownRequeuesRunningAnalyses(@TempDir Path dir) throws Exception {
        Path project = TestSupport.fixture("projects/java-crypto-package");
        Path marker = dir.resolve("cdxgen-started");
        var application = new com.chiffrium.MainAccess(AppConfig.from(Map.of(
                "DATA_DIR", dir.resolve("data").toString(),
                "ALLOWED_LOCAL_ROOTS", project.getParent().toString(),
                "OSV_ENABLED", "false",
                "CDXGEN_COMMAND", slowCdxgen(dir, marker).toString())));
        try {
            Actor admin = application.admin(PASSWORD);
            String id = application.analyses().submit(admin,
                    List.of(new AnalysisRequest(project.toString(), null, false, true, false, null)), null).get(0).id();
            await(() -> Files.exists(marker), "cdxgen démarré");
            assertThat(application.analyses().activity().running()).isEqualTo(1);

            Instant before = Instant.now();
            application.analyses().close();
            assertThat(Duration.between(before, Instant.now())).as("arrêt rapide").isLessThan(Duration.ofSeconds(12));
            AnalysisJob requeued = application.analyses().find(admin, id).orElseThrow();
            assertThat(requeued.status()).isEqualTo(AnalysisStatus.QUEUED);
            assertThat(requeued.startedAt()).isNull();
            assertThat(requeued.steps()).isEmpty();
            assertThat(application.audit().search(null, "ANALYSIS_FAILED", 10, 0)).isEmpty();
        } finally {
            application.close();
        }
    }

    /** cdxgen factice : répond à --version, puis ne se termine jamais (jusqu'à ce qu'on le tue). */
    private static Path slowCdxgen(Path dir, Path marker) throws IOException {
        boolean windows = System.getProperty("os.name").toLowerCase().contains("win");
        Path script = dir.resolve(windows ? "cdxgen.cmd" : "cdxgen");
        if (windows) {
            Files.writeString(script, "@echo off\r\nif \"%1\"==\"--version\" (echo 11.7.0& exit /b 0)\r\n"
                    + "echo started> \"" + marker + "\"\r\nping -n 600 127.0.0.1 > nul\r\n");
        } else {
            Files.writeString(script, "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 11.7.0; exit 0; fi\n"
                    + "echo started > '" + marker + "'\nsleep 600\n");
            script.toFile().setExecutable(true);
        }
        return script;
    }

    private static void await(java.util.function.BooleanSupplier condition, String what) throws InterruptedException {
        Instant deadline = Instant.now().plus(WAIT);
        while (!condition.getAsBoolean()) {
            if (Instant.now().isAfter(deadline)) {
                throw new AssertionError("Délai dépassé : " + what);
            }
            Thread.sleep(100);
        }
    }

    private static AnalysisJob await(String id, com.chiffrium.MainAccess application, Predicate<AnalysisJob> done)
            throws InterruptedException {
        Instant deadline = Instant.now().plus(WAIT);
        while (Instant.now().isBefore(deadline)) {
            AnalysisJob job = application.analyses().find(application.system(), id).orElseThrow();
            if (done.test(job)) {
                return job;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("Analyse non terminée : " + id);
    }
}
