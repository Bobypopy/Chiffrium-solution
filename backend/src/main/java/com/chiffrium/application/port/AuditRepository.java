package com.chiffrium.application.port;

import com.chiffrium.domain.security.AuditEvent;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Journal d'audit en ajout seul : aucune modification n'est exposée ; la seule suppression est la purge de
 * rétention des entrées déjà exportées, qui laisse un point de reprise pour la vérification de la chaîne.
 */
public interface AuditRepository {

    /**
     * Le numéro de séquence vient d'être pris par une autre instance : l'appelant doit relire la dernière
     * entrée et rechaîner la sienne.
     */
    class SequenceTakenException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public SequenceTakenException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    void append(AuditEvent event);

    /**
     * Construit puis écrit une entrée en sérialisant "lire la dernière" et "écrire la suivante". Les dépôts
     * en base le font dans une transaction qui verrouille la dernière ligne ; l'implémentation par défaut
     * convient aux dépôts d'une seule instance.
     *
     * @param builder reçoit la dernière entrée connue (vide si le journal est vide) et rend l'entrée à écrire
     */
    default AuditEvent appendChained(java.util.function.Function<Optional<AuditEvent>, AuditEvent> builder) {
        AuditEvent event = builder.apply(last());
        append(event);
        return event;
    }

    Optional<AuditEvent> last();

    /** Entrées de la plus récente à la plus ancienne, filtrées (critères null = pas de filtre). */
    List<AuditEvent> search(String actor, String action, int limit, int offset);

    /** Toutes les entrées conservées dans l'ordre chronologique (vérification de la chaîne). */
    List<AuditEvent> all();

    /** Entrées de numéro strictement supérieur, dans l'ordre (export incrémental). */
    List<AuditEvent> after(long sequence, int limit);

    /**
     * Point de reprise après purge.
     *
     * @param sequence dernière entrée purgée
     * @param hash     son empreinte (attendue comme "précédente" de la première entrée conservée)
     */
    record Checkpoint(long sequence, String hash) {
    }

    Optional<Checkpoint> checkpoint();

    /** Supprime les entrées jusqu'à {@code upTo.sequence()} incluse et enregistre le point de reprise. */
    void purgeUpTo(Checkpoint upTo);

    /**
     * Ancrage externe : dernière entrée exportée vers un stockage hors de la base.
     *
     * @param sequence   numéro de l'entrée
     * @param hash       empreinte exportée
     * @param exportedAt date de l'export
     * @param target     destination (dossier, URL)
     */
    record Anchor(long sequence, String hash, Instant exportedAt, String target) {
    }

    void addAnchor(Anchor anchor);

    Optional<Anchor> lastAnchor();
}
