package com.chiffrium.application.security;

import com.chiffrium.SecurityFixture;
import com.chiffrium.TestSupport;
import com.chiffrium.application.port.AuditSink;
import com.chiffrium.infrastructure.audit.DirectoryAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Archivage externe, détection de troncature et rétention du journal d'audit.
 */
class AuditArchiveTest {

    private static final int RETENTION_DAYS = 180;

    private SecurityFixture fx;
    private Path exportDir;
    private final AtomicInteger retention = new AtomicInteger();

    @BeforeEach
    void open(@TempDir Path dir) {
        fx = new SecurityFixture(dir);
        exportDir = dir.resolve("worm");
        fx.setupAdmin();
    }

    @AfterEach
    void close() {
        fx.close();
    }

    private AuditArchiveService archive() {
        List<AuditSink> sinks = List.of(new DirectoryAuditSink(exportDir, TestSupport.MAPPER, fx.clock));
        return new AuditArchiveService(fx.auditRepository, fx.audit, () -> sinks, retention::get, fx.clock);
    }

    @Test
    void exportsIncrementallyAndDetectsTailTruncation() throws Exception {
        AuditArchiveService archive = archive();
        int first = archive.exportPending();
        fx.audit.record(Actor.SYSTEM, "TEST", "x", null);
        int second = archive.exportPending();

        assertThat(first).isPositive();
        assertThat(second).isEqualTo(1);
        long exportedLines;
        try (Stream<Path> files = Files.list(exportDir)) {
            exportedLines = files.mapToLong(f -> TestSupport.lines(f).size()).sum();
        }
        assertThat(exportedLines).isEqualTo(first + second);
        assertThat(fx.audit.verify().intact()).isTrue();
        assertThat(fx.audit.verify().anchoredUpTo()).isNotNull();

        // Un attaquant supprime la dernière entrée : la chaîne restante est cohérente, mais l'ancrage le révèle.
        try (Connection c = fx.database.connection();
             PreparedStatement st = c.prepareStatement(
                     "DELETE FROM audit_log WHERE sequence = (SELECT MAX(sequence) FROM audit_log)")) {
            st.executeUpdate();
        }
        AuditService.Verification verification = fx.audit.verify();
        assertThat(verification.intact()).isFalse();
        assertThat(verification.problem()).contains("tronquée");
    }

    @Test
    void retentionOnlyPurgesArchivedEntriesAndKeepsTheChainVerifiable() {
        retention.set(RETENTION_DAYS);
        AuditArchiveService archive = archive();
        fx.clock.advance(Duration.ofDays(RETENTION_DAYS + 1));
        assertThat(archive.applyRetention()).as("rien d'archivé : rien de purgé").isZero();

        archive.exportPending();
        int purged = archive.applyRetention();
        assertThat(purged).isPositive();
        fx.audit.record(Actor.SYSTEM, "AFTER_PURGE", null, null);

        AuditService.Verification verification = fx.audit.verify();
        assertThat(verification.intact()).isTrue();
        assertThat(verification.purgedUpTo()).isNotNull();
        assertThat(fx.audit.all()).extracting(e -> e.action()).contains("AUDIT_PURGED", "AFTER_PURGE")
                .doesNotContain("SETUP_COMPLETED");
    }
}
