package com.chiffrium.application.port;

import com.chiffrium.domain.security.Notification;

import java.time.Instant;
import java.util.List;

/**
 * Persistance des notifications des utilisateurs.
 */
public interface NotificationRepository {

    void save(Notification notification);

    /** Notifications d'un utilisateur, des plus récentes aux plus anciennes. */
    List<Notification> forUser(String userId, boolean unreadOnly, int limit);

    long unreadCount(String userId);

    /** Marque comme lues (toutes si {@code ids} est vide). */
    void markRead(String userId, List<String> ids, Instant now);

    /** Purge les notifications lues avant la date. */
    int purgeReadBefore(Instant limit);
}
