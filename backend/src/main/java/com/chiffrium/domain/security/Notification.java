package com.chiffrium.domain.security;

import java.time.Instant;

/**
 * Notification adressée à un utilisateur dans l'application (centre de notifications).
 *
 * @param userId    destinataire
 * @param kind      type (ex. GROUP_INVITATION, ANALYSIS_FINISHED), pour l'icône et le filtrage
 * @param title     intitulé court
 * @param body      détail
 * @param link      lien interne vers l'objet concerné (ex. #/report/...), null si aucun
 * @param createdAt date
 * @param readAt    date de lecture (null si non lue)
 */
public record Notification(String id, String userId, String kind, String title, String body, String link,
                           Instant createdAt, Instant readAt) {

    public static final int MAX_TITLE_LENGTH = 200;
    public static final int MAX_BODY_LENGTH = 1_000;
}
