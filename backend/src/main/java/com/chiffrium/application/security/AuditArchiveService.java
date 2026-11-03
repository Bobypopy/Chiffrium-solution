package com.chiffrium.application.security;

import com.chiffrium.application.port.AuditRepository;
import com.chiffrium.application.port.AuditSink;
import com.chiffrium.domain.security.AuditEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.IntSupplier;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Archivage externe et rétention du journal d'audit.
 * <ul>
 *   <li>{@link #exportPending()} publie les nouvelles entrées vers toutes les destinations configurées, puis
 *       enregistre un ancrage (dernière entrée publiée) : la vérification détecte ensuite toute troncature.</li>
 *   <li>{@link #applyRetention()} ne purge que des entrées déjà archivées et plus anciennes que la durée de
 *       conservation, et laisse un point de reprise : la chaîne reste vérifiable.</li>
 * </ul>
 */
public final class AuditArchiveService {

    private static final Logger LOG = LoggerFactory.getLogger(AuditArchiveService.class);
    static final int BATCH_SIZE = 500;

    private final AuditRepository repository;
    private final AuditService audit;
    private final Supplier<List<AuditSink>> sinks;
    private final IntSupplier retentionDays;
    private final Clock clock;

    public AuditArchiveService(AuditRepository repository, AuditService audit, Supplier<List<AuditSink>> sinks,
                               IntSupplier retentionDays, Clock clock) {
        this.repository = repository;
        this.audit = audit;
        this.sinks = sinks;
        this.retentionDays = retentionDays;
        this.clock = clock;
    }

    /**
     * Dernier résultat d'archivage, montré dans Administration > Journal d'audit.
     *
     * @param attemptedAt dernier essai (null si aucun)
     * @param succeededAt dernier essai réussi (null si aucun)
     * @param targets     destinations configurées
     * @param error       message du dernier échec (null si le dernier essai a réussi)
     */
    public record ExportState(Instant attemptedAt, Instant succeededAt, String targets, String error) {
    }

    private volatile ExportState state = new ExportState(null, null, null, null);

    public ExportState state() {
        return state;
    }

    /** @return nombre d'entrées publiées */
    public synchronized int exportPending() {
        List<AuditSink> targets = sinks.get();
        if (targets.isEmpty()) {
            state = new ExportState(state.attemptedAt(), state.succeededAt(), null, null);
            return 0;
        }
        String targetNames = targets.stream().map(AuditSink::name).collect(Collectors.joining(", "));
        long from = repository.lastAnchor().map(AuditRepository.Anchor::sequence)
                .orElseGet(() -> repository.checkpoint().map(AuditRepository.Checkpoint::sequence).orElse(0L));
        int exported = 0;
        Instant now = clock.instant();
        while (true) {
            List<AuditEvent> batch = repository.after(from, BATCH_SIZE);
            if (batch.isEmpty()) {
                state = new ExportState(now, exported > 0 ? now : state.succeededAt(), targetNames, null);
                return exported;
            }
            for (AuditSink sink : targets) {
                try {
                    sink.publish(batch);
                } catch (RuntimeException e) {
                    LOG.error("Archivage du journal d'audit vers {} impossible : {}", sink.name(), e.getMessage());
                    state = new ExportState(now, state.succeededAt(), targetNames,
                            sink.name() + " : " + e.getMessage());
                    return exported;
                }
            }
            AuditEvent last = batch.get(batch.size() - 1);
            repository.addAnchor(new AuditRepository.Anchor(last.sequence(), last.hash(), clock.instant(), targetNames));
            exported += batch.size();
            from = last.sequence();
        }
    }

    /** @return nombre d'entrées purgées */
    public synchronized int applyRetention() {
        int days = retentionDays.getAsInt();
        if (days <= 0) {
            return 0;
        }
        long anchored = repository.lastAnchor().map(AuditRepository.Anchor::sequence).orElse(0L);
        Instant limit = clock.instant().minus(Duration.ofDays(days));
        AuditEvent lastPurgeable = null;
        for (AuditEvent event : repository.all()) {
            if (event.sequence() > anchored || !event.timestamp().isBefore(limit)) {
                break;
            }
            lastPurgeable = event;
        }
        if (lastPurgeable == null) {
            return 0;
        }
        long before = repository.checkpoint().map(AuditRepository.Checkpoint::sequence).orElse(0L);
        repository.purgeUpTo(new AuditRepository.Checkpoint(lastPurgeable.sequence(), lastPurgeable.hash()));
        int purged = (int) (lastPurgeable.sequence() - before);
        audit.record(Actor.SYSTEM, "AUDIT_PURGED", null, purged + " entrée(s) archivée(s) de plus de " + days + " jours");
        return purged;
    }
}
