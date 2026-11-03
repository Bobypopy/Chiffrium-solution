package com.chiffrium.infrastructure.db;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Différences SQL entre les moteurs supportés : types (substitués dans les migrations via {@code ${NOM}})
 * et insertion-ou-mise-à-jour.
 */
enum Dialect {
    /** Base embarquée chiffrée (bureau, petit serveur). */
    H2(Map.of("BINARY", "VARBINARY(65536)", "TEXT", "CHARACTER LARGE OBJECT")),
    /** Serveur d'équipe multi-utilisateurs. */
    POSTGRESQL(Map.of("BINARY", "BYTEA", "TEXT", "TEXT"));

    private final Map<String, String> types;

    Dialect(Map<String, String> types) {
        this.types = types;
    }

    /** Remplace les jetons {@code ${BINARY}}, {@code ${TEXT}} d'une migration. */
    String resolve(String sql) {
        String resolved = sql;
        for (Map.Entry<String, String> type : types.entrySet()) {
            resolved = resolved.replace("${" + type.getKey() + "}", type.getValue());
        }
        return resolved;
    }

    /**
     * Requête d'insertion ou de mise à jour selon la clé.
     *
     * @param table   table
     * @param keys    colonnes de la clé
     * @param columns toutes les colonnes, dans l'ordre des paramètres
     */
    String upsert(String table, List<String> keys, List<String> columns) {
        String columnList = String.join(", ", columns);
        String placeholders = columns.stream().map(c -> "?").collect(Collectors.joining(", "));
        if (this == H2) {
            return "MERGE INTO " + table + " (" + columnList + ") KEY (" + String.join(", ", keys) + ") VALUES ("
                    + placeholders + ")";
        }
        List<String> updates = columns.stream().filter(c -> !keys.contains(c)).map(c -> c + " = EXCLUDED." + c).toList();
        return "INSERT INTO " + table + " (" + columnList + ") VALUES (" + placeholders + ") ON CONFLICT ("
                + String.join(", ", keys) + ") " + (updates.isEmpty() ? "DO NOTHING" : "DO UPDATE SET "
                + String.join(", ", updates));
    }

    static List<String> columns(String commaSeparated) {
        return Arrays.stream(commaSeparated.split(",")).map(String::strip).toList();
    }
}
