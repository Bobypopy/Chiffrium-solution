package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Statut de conformité d'un actif vis-à-vis de la politique cryptographique.
 * L'ordre de déclaration va du plus sûr au plus risqué ({@link #worst} s'appuie dessus).
 */
public enum PolicyStatus {
    RECOMMENDED,
    ACCEPTABLE,
    UNKNOWN,
    DEPRECATED,
    DISALLOWED;

    @JsonValue
    public String id() {
        return name().toLowerCase(Locale.ROOT);
    }

    /**
     * Statut lu depuis l'API ou un catalogue importé. Une valeur inconnue est refusée : l'accepter
     * silencieusement (en la ramenant à UNKNOWN) ferait passer un algorithme interdit pour non classé, et les
     * analyses suivantes cesseraient de le signaler.
     */
    @JsonCreator
    public static PolicyStatus fromId(String value) {
        return Arrays.stream(values())
                .filter(s -> s.name().equalsIgnoreCase(value))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Statut inconnu : " + value + " (attendu : "
                        + Arrays.stream(values()).map(PolicyStatus::id).collect(Collectors.joining(", ")) + ")"));
    }

    public static PolicyStatus worst(PolicyStatus a, PolicyStatus b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }

    public boolean isProblematic() {
        return this == DEPRECATED || this == DISALLOWED;
    }
}
