package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Locale;

/**
 * Cycle de vie d'une analyse.
 */
public enum AnalysisStatus {
    QUEUED, RUNNING, SUCCEEDED, FAILED,
    /** Arrêtée à la demande d'un utilisateur (en attente ou en cours). */
    CANCELLED;

    @JsonValue
    public String id() {
        return name().toLowerCase(Locale.ROOT);
    }

    public boolean isTerminal() {
        return this == SUCCEEDED || this == FAILED || this == CANCELLED;
    }
}
