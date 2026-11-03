package com.chiffrium.domain.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;

/**
 * Proposition d'adhésion à un groupe, dans les deux sens :
 * <ul>
 *   <li>{@link Kind#INVITATION} : un responsable invite ; seul l'invité peut accepter ;</li>
 *   <li>{@link Kind#JOIN_REQUEST} : un utilisateur demande à rejoindre un groupe public ; un responsable accepte.</li>
 * </ul>
 *
 * @param groupName   nom du groupe (affichage)
 * @param userId      personne concernée (invitée ou demandeuse)
 * @param username    son identifiant
 * @param kind        sens de la proposition
 * @param manager     rôle de responsable proposé (invitation uniquement)
 * @param message     mot d'accompagnement
 * @param createdBy   auteur de la proposition
 * @param status      état
 * @param respondedBy auteur de la réponse
 * @param createdAt   date de la proposition
 * @param respondedAt date de la réponse
 */
public record GroupInvitation(String id, String groupId, String groupName, String userId, String username, Kind kind,
                              boolean manager, String message, String createdBy, Status status, String respondedBy,
                              Instant createdAt, Instant respondedAt) {

    public static final int MAX_MESSAGE_LENGTH = 500;

    /** Sens de la proposition. */
    public enum Kind {
        INVITATION, JOIN_REQUEST;

        @JsonValue
        public String id() {
            return name().toLowerCase(Locale.ROOT).replace('_', '-');
        }

        @JsonCreator
        public static Kind fromId(String value) {
            return Arrays.stream(values()).filter(k -> k.id().equalsIgnoreCase(value) || k.name().equalsIgnoreCase(value))
                    .findFirst().orElseThrow(() -> new IllegalArgumentException("Type inconnu : " + value));
        }
    }

    /** Cycle de vie. */
    public enum Status {
        PENDING, ACCEPTED, DECLINED, CANCELLED;

        @JsonValue
        public String id() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    public GroupInvitation answered(Status answer, String by, Instant now) {
        return new GroupInvitation(id, groupId, groupName, userId, username, kind, manager, message, createdBy, answer,
                by, createdAt, now);
    }
}
