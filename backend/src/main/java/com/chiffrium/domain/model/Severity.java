package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;
import java.util.Locale;

/**
 * Sévérité d'un constat, du moins grave au plus grave.
 */
public enum Severity {
    NONE,
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    @JsonValue
    public String id() {
        return name().toLowerCase(Locale.ROOT);
    }

    @JsonCreator
    public static Severity fromId(String value) {
        return Arrays.stream(values())
                .filter(s -> s.name().equalsIgnoreCase(value))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Sévérité inconnue : " + value));
    }

    public static Severity worst(Severity a, Severity b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }

    /** Niveau immédiatement inférieur (sans descendre sous {@link #INFO}). */
    public Severity lower() {
        return ordinal() <= INFO.ordinal() ? this : values()[ordinal() - 1];
    }
}
