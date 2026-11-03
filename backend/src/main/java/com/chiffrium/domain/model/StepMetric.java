package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Locale;

/**
 * Mesure d'une étape du pipeline d'analyse (remplace l'ancien file_metrics.json).
 *
 * @param step       nom de l'étape
 * @param status     résultat
 * @param durationMs durée en millisecondes
 * @param message    détail (erreur, nombre d'éléments produits...)
 */
public record StepMetric(String step, Status status, long durationMs, String message) {

    public enum Status {
        SUCCEEDED, FAILED, SKIPPED;

        @JsonValue
        public String id() {
            return name().toLowerCase(Locale.ROOT);
        }
    }
}
