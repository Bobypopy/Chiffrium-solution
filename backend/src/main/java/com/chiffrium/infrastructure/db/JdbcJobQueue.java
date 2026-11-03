package com.chiffrium.infrastructure.db;

import com.chiffrium.application.port.JobQueue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * File partagée entre répliques, dans la table {@code analyses} : une réplique réserve une analyse par une mise à
 * jour conditionnelle ({@code ... WHERE status = 'QUEUED'}), atomique dans toute base SQL - deux répliques ne
 * peuvent donc pas exécuter la même analyse. Un signe de vie régulier permet de détecter une réplique arrêtée.
 */
public final class JdbcJobQueue implements JobQueue {

    private static final String QUEUED = "QUEUED";
    private static final String RUNNING = "RUNNING";
    /** Candidates examinées par tentative de réservation. */
    private static final int CANDIDATES = 5;
    private static final Duration POLL_INTERVAL = Duration.ofSeconds(1);

    private final Jdbc jdbc;
    private final String workerId;
    private final Clock clock;

    /**
     * @param workerId identifiant de la réplique (nom d'hôte du pod, par exemple)
     */
    public JdbcJobQueue(Database database, String workerId, Clock clock) {
        this.jdbc = new Jdbc(database);
        this.workerId = workerId;
        this.clock = clock;
    }

    @Override
    public void enqueue(String analysisId) {
        // L'analyse est déjà enregistrée avec le statut QUEUED : les répliques la verront à leur prochain passage.
    }

    @Override
    public Optional<String> take(Duration wait) throws InterruptedException {
        Instant deadline = clock.instant().plus(wait);
        do {
            List<String> candidates = jdbc.query("SELECT id FROM analyses WHERE status = ? ORDER BY created_at LIMIT ?",
                    rs -> rs.getString(1), QUEUED, CANDIDATES);
            for (String id : candidates) {
                Instant now = clock.instant();
                int claimed = jdbc.update("UPDATE analyses SET status = ?, worker = ?, heartbeat_at = ? "
                        + "WHERE id = ? AND status = ?", RUNNING, workerId, now, id, QUEUED);
                if (claimed == 1) {
                    return Optional.of(id);
                }
            }
            Thread.sleep(Math.min(POLL_INTERVAL.toMillis(), Math.max(0, Duration.between(clock.instant(), deadline)
                    .toMillis())));
        } while (clock.instant().isBefore(deadline));
        return Optional.empty();
    }

    @Override
    public int pending() {
        return jdbc.queryOne("SELECT COUNT(*) FROM analyses WHERE status = ?", rs -> rs.getInt(1), QUEUED).orElse(0);
    }

    @Override
    public void heartbeat(String analysisId) {
        jdbc.update("UPDATE analyses SET heartbeat_at = ? WHERE id = ? AND worker = ?", clock.instant(), analysisId,
                workerId);
    }

    @Override
    public List<String> abandoned(Duration staleAfter) {
        return jdbc.query("SELECT id FROM analyses WHERE status = ? AND heartbeat_at < ?", rs -> rs.getString(1),
                RUNNING, clock.instant().minus(staleAfter));
    }
}
