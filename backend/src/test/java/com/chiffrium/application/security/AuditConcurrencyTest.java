package com.chiffrium.application.security;

import com.chiffrium.application.port.AuditRepository;
import com.chiffrium.domain.security.AuditEvent;
import com.chiffrium.domain.security.Role;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plusieurs instances écrivent dans le même journal : la perdante doit rechaîner son entrée au lieu de faire
 * échouer l'action de l'utilisateur (constaté en charge : une connexion renvoyait HTTP 500).
 */
class AuditConcurrencyTest {

    private static final Actor ACTOR = new Actor("u1", "alice", Role.ANALYST, "127.0.0.1");

    /** Dépôt qui simule une autre instance : les premières écritures se font voler leur numéro. */
    private static final class ContestedRepository implements AuditRepository {

        private final List<AuditEvent> entries = new ArrayList<>();
        private final AtomicInteger conflictsLeft;

        ContestedRepository(int conflicts) {
            this.conflictsLeft = new AtomicInteger(conflicts);
        }

        @Override
        public void append(AuditEvent event) {
            if (conflictsLeft.getAndDecrement() > 0) {
                // L'autre instance a pris ce numéro juste avant nous.
                entries.add(AuditEvent.chained(event.sequence(), event.timestamp(), "autre-instance", "AUTRE",
                        null, null, null, event.previousHash()));
                throw new SequenceTakenException("numéro " + event.sequence() + " déjà pris", null);
            }
            entries.add(event);
        }

        @Override
        public Optional<AuditEvent> last() {
            return entries.isEmpty() ? Optional.empty() : Optional.of(entries.get(entries.size() - 1));
        }

        @Override
        public List<AuditEvent> search(String actor, String action, int limit, int offset) {
            return List.copyOf(entries);
        }

        @Override
        public List<AuditEvent> all() {
            return List.copyOf(entries);
        }

        @Override
        public List<AuditEvent> after(long sequence, int limit) {
            return entries.stream().filter(e -> e.sequence() > sequence).limit(limit).toList();
        }

        @Override
        public Optional<Checkpoint> checkpoint() {
            return Optional.empty();
        }

        @Override
        public void purgeUpTo(Checkpoint upTo) {
            entries.removeIf(e -> e.sequence() <= upTo.sequence());
        }

        @Override
        public void addAnchor(Anchor anchor) {
            // Sans archivage externe dans ce test.
        }

        @Override
        public Optional<Anchor> lastAnchor() {
            return Optional.empty();
        }
    }

    private static AuditService service(ContestedRepository repository) {
        return new AuditService(repository, Clock.fixed(Instant.parse("2026-09-23T10:15:30Z"), ZoneOffset.UTC));
    }

    @Test
    void rechaineQuandUneAutreInstancePrendLeNumero() {
        ContestedRepository repository = new ContestedRepository(2);
        AuditService audit = service(repository);

        AuditEvent ecrit = audit.record(ACTOR, "LOGIN_SUCCESS", "alice", "connexion");

        assertThat(ecrit.sequence()).isEqualTo(3);
        assertThat(repository.all()).hasSize(3);
        assertThat(ecrit.previousHash()).isEqualTo(repository.all().get(1).hash());
        assertThat(audit.verify().intact()).isTrue();
    }

    @Test
    void abandonneApresPlusieursEchecsPlutotQueBoucler() {
        ContestedRepository repository = new ContestedRepository(50);
        AuditService audit = service(repository);

        assertThat(org.assertj.core.api.Assertions.catchThrowable(
                () -> audit.record(ACTOR, "LOGIN_SUCCESS", "alice", "connexion")))
                .isInstanceOf(AuditRepository.SequenceTakenException.class);
    }
}
