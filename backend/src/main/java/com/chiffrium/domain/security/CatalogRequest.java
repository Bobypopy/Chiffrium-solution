package com.chiffrium.domain.security;

import com.chiffrium.domain.policy.AlgorithmDefinition;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;

/**
 * Demande de modification du catalogue (ex. classer un OID comme interdit dans l'organisation), soumise par un
 * utilisateur et validée ou refusée par un administrateur. Toutes les étapes sont tracées dans l'audit.
 *
 * @param kind          ajout, modification ou suppression d'une entrée
 * @param algorithmId   entrée concernée
 * @param proposal      entrée proposée (null pour une suppression)
 * @param justification motif (référence normative, besoin métier...)
 * @param requestedBy   demandeur
 * @param groupId       groupe du demandeur au moment de la demande (null si aucun)
 * @param status        état
 * @param reviewedBy    administrateur ayant statué
 * @param reviewComment commentaire de décision
 * @param createdAt     date de la demande
 * @param reviewedAt    date de la décision
 */
public record CatalogRequest(
        String id,
        Kind kind,
        String algorithmId,
        AlgorithmDefinition proposal,
        String justification,
        String requestedBy,
        String groupId,
        Status status,
        String reviewedBy,
        String reviewComment,
        Instant createdAt,
        Instant reviewedAt) {

    public static final int MAX_TEXT_LENGTH = 2_000;

    /** Nature de la modification demandée. */
    public enum Kind {
        CREATE, UPDATE, DELETE;

        @JsonValue
        public String id() {
            return name().toLowerCase(Locale.ROOT);
        }

        @JsonCreator
        public static Kind fromId(String value) {
            return Arrays.stream(values()).filter(k -> k.name().equalsIgnoreCase(value)).findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Type de demande inconnu : " + value));
        }
    }

    /** Cycle de vie : en attente, puis acceptée, refusée ou retirée par son auteur. */
    public enum Status {
        PENDING, APPROVED, REJECTED, WITHDRAWN;

        @JsonValue
        public String id() {
            return name().toLowerCase(Locale.ROOT);
        }

        @JsonCreator
        public static Status fromId(String value) {
            return Arrays.stream(values()).filter(s -> s.name().equalsIgnoreCase(value)).findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("État de demande inconnu : " + value));
        }
    }

    public CatalogRequest decided(Status decision, String reviewer, String comment, Instant now) {
        return new CatalogRequest(id, kind, algorithmId, proposal, justification, requestedBy, groupId, decision,
                reviewer, comment, createdAt, now);
    }
}
