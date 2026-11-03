package com.chiffrium.application.security;

import com.chiffrium.application.port.AuditRepository;
import com.chiffrium.domain.security.AuditEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

/**
 * Journal d'audit infalsifiable : chaque action sensible est enregistrée avec l'empreinte de la précédente.
 * {@link #verify()} recalcule la chaîne et signale la première entrée altérée.
 */
public final class AuditService {

    private static final Logger LOG = LoggerFactory.getLogger(AuditService.class);
    private static final int MAX_DETAILS_LENGTH = 1_000;
    private static final int MAX_PAGE_SIZE = 500;

    private final AuditRepository repository;
    /** Tentatives d'écriture avant abandon quand plusieurs instances écrivent en même temps. */
    private static final int MAX_APPEND_ATTEMPTS = 5;

    private final Clock clock;

    public AuditService(AuditRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    /**
     * Enregistre une action. Synchronisé : la chaîne reste strictement ordonnée dans cette instance. Avec
     * plusieurs instances, deux écritures peuvent viser le même numéro : la perdante relit la dernière entrée
     * et rechaîne la sienne, plutôt que de faire échouer l'action de l'utilisateur.
     */
    public synchronized AuditEvent record(Actor actor, String action, String target, String details) {
        for (int essai = 1; essai < MAX_APPEND_ATTEMPTS; essai++) {
            try {
                return append(actor, action, target, details);
            } catch (AuditRepository.SequenceTakenException conflit) {
                LOG.debug("Numéro d'audit déjà pris (essai {}/{}) : rechaînage", essai, MAX_APPEND_ATTEMPTS);
            }
        }
        return append(actor, action, target, details);
    }

    private AuditEvent append(Actor actor, String action, String target, String details) {
        AuditEvent event = repository.appendChained(last -> {
            AuditEvent previous = last.orElse(null);
            // Journal entièrement purgé : la chaîne reprend au point de reprise.
            AuditRepository.Checkpoint checkpoint = previous == null ? repository.checkpoint().orElse(null) : null;
            long sequence = previous != null ? previous.sequence() + 1
                    : checkpoint != null ? checkpoint.sequence() + 1 : 1;
            String previousHash = previous != null ? previous.hash()
                    : checkpoint != null ? checkpoint.hash() : AuditEvent.GENESIS_HASH;
            // Précision milliseconde : l'horodatage doit être relu à l'identique pour recalculer l'empreinte.
            Instant now = clock.instant().truncatedTo(ChronoUnit.MILLIS);
            return AuditEvent.chained(sequence, now, actor.username(), action, target, truncate(details),
                    actor.sourceIp(), previousHash);
        });
        LOG.info("AUDIT {} {} {} {}", actor.username(), action, target == null ? "" : target,
                details == null ? "" : truncate(details));
        return event;
    }

    public List<AuditEvent> search(String actor, String action, int limit, int offset) {
        return repository.search(blankToNull(actor), blankToNull(action), Math.min(Math.max(limit, 1), MAX_PAGE_SIZE),
                Math.max(offset, 0));
    }

    /** Journal complet dans l'ordre chronologique (export pour archivage externe). */
    public List<AuditEvent> all() {
        return repository.all();
    }

    /**
     * @param intact          vrai si toute la chaîne est cohérente
     * @param entries         nombre d'entrées vérifiées
     * @param firstBrokenSeq  première entrée incohérente (null si intact)
     * @param problem         explication (null si intact)
     * @param anchoredUpTo    dernière entrée archivée à l'extérieur (null si aucun archivage)
     * @param purgedUpTo      dernière entrée purgée par la rétention (null si aucune purge)
     */
    public record Verification(boolean intact, int entries, Long firstBrokenSeq, String problem, Long anchoredUpTo,
                               Long purgedUpTo) {
    }

    /**
     * Recalcule la chaîne depuis le point de reprise et contrôle la dernière entrée archivée : une modification,
     * une suppression intermédiaire ou une troncature de la fin du journal (après archivage) sont détectées.
     */
    public Verification verify() {
        List<AuditEvent> all = repository.all();
        Optional<AuditRepository.Checkpoint> checkpoint = repository.checkpoint();
        Optional<AuditRepository.Anchor> anchor = repository.lastAnchor();
        Long anchoredUpTo = anchor.map(AuditRepository.Anchor::sequence).orElse(null);
        Long purgedUpTo = checkpoint.map(AuditRepository.Checkpoint::sequence).orElse(null);
        String expectedPrevious = checkpoint.map(AuditRepository.Checkpoint::hash).orElse(AuditEvent.GENESIS_HASH);
        for (AuditEvent event : all) {
            if (!event.previousHash().equals(expectedPrevious)) {
                return new Verification(false, all.size(), event.sequence(),
                        "entrée précédente supprimée ou modifiée", anchoredUpTo, purgedUpTo);
            }
            if (!event.isIntact()) {
                return new Verification(false, all.size(), event.sequence(), "contenu modifié", anchoredUpTo,
                        purgedUpTo);
            }
            expectedPrevious = event.hash();
        }
        if (anchor.isPresent() && (purgedUpTo == null || anchor.get().sequence() > purgedUpTo)) {
            AuditRepository.Anchor a = anchor.get();
            boolean found = all.stream().anyMatch(e -> e.sequence() == a.sequence() && e.hash().equals(a.hash()));
            if (!found) {
                return new Verification(false, all.size(), a.sequence(),
                        "entrée archivée absente ou différente : fin du journal tronquée ou remplacée", anchoredUpTo,
                        purgedUpTo);
            }
        }
        return new Verification(true, all.size(), null, null, anchoredUpTo, purgedUpTo);
    }

    private static String truncate(String value) {
        if (value == null) {
            return null;
        }
        return value.length() > MAX_DETAILS_LENGTH ? value.substring(0, MAX_DETAILS_LENGTH) + "..." : value;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
