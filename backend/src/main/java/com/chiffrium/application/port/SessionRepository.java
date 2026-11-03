package com.chiffrium.application.port;

import java.time.Instant;
import java.util.Optional;

/**
 * Sessions ouvertes. Seule l'empreinte SHA-256 du jeton est stockée : une fuite de la base ne permet pas
 * de réutiliser les sessions.
 */
public interface SessionRepository {

    void create(Session session);

    Optional<Session> findByTokenHash(String tokenHash);

    void touch(String tokenHash, Instant lastSeenAt);

    void delete(String tokenHash);

    void deleteByUser(String userId);

    /** Supprime les sessions expirées ; renvoie le nombre supprimé. */
    int deleteExpired(Instant now);

    /**
     * @param tokenHash  empreinte du jeton
     * @param userId     utilisateur
     * @param createdAt  ouverture
     * @param lastSeenAt dernière activité (expiration par inactivité)
     * @param expiresAt  expiration absolue
     * @param sourceIp   adresse d'ouverture
     */
    record Session(String tokenHash, String userId, Instant createdAt, Instant lastSeenAt, Instant expiresAt,
                   String sourceIp) {
    }
}
