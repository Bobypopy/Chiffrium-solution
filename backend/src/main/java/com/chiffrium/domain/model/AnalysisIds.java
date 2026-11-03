package com.chiffrium.domain.model;

import java.util.regex.Pattern;

/**
 * Identifiants d'analyse : des UUID. Toute autre valeur est refusée (protection contre "../" dans les chemins
 * et les clés de stockage).
 */
public final class AnalysisIds {

    private static final Pattern UUID = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private AnalysisIds() {
    }

    public static boolean isValid(String id) {
        return id != null && UUID.matcher(id).matches();
    }
}
