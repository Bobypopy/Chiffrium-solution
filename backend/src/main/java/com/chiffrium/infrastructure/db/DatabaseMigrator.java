package com.chiffrium.infrastructure.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Recopie le contenu d'une base vers une autre : passage de H2 (poste ou petit serveur) à PostgreSQL
 * (serveur d'équipe), sans reprise manuelle.
 *
 * <p>Le schéma de la cible est créé par ses propres migrations à l'ouverture ; ce migrateur ne déplace que les
 * données, table par table, dans l'ordre des clés étrangères, et dans une seule transaction : en cas d'erreur,
 * la cible reste telle qu'elle était. La base d'origine n'est jamais modifiée.
 *
 * <p>Ce qui vit hors de la base - rapports d'analyse, artefacts, clé maîtresse - se recopie séparément
 * (dossier de données) : la clé maîtresse est indispensable pour relire les réglages chiffrés.
 */
public final class DatabaseMigrator {

    private static final Logger LOG = LoggerFactory.getLogger(DatabaseMigrator.class);

    /**
     * Tables dans un ordre qui respecte les clés étrangères (un parent avant ses enfants). {@code
     * schema_version} en est absente : chaque base tient son propre journal de migrations.
     */
    private static final List<String> TABLES = List.of(
            "users", "user_groups", "group_members", "group_invitations", "sessions", "favorites",
            "notifications", "catalog_requests", "audit_log", "audit_checkpoint", "audit_anchors",
            "settings", "analyses");
    private static final int BATCH_SIZE = 500;

    private DatabaseMigrator() {
    }

    /** Nombre de lignes copiées pour une table. */
    public record TableResult(String table, int rows) {
    }

    /** Bilan de la recopie, dans l'ordre des tables. */
    public record Result(List<TableResult> tables) {

        public int total() {
            return tables.stream().mapToInt(TableResult::rows).sum();
        }
    }

    /**
     * Copie toutes les tables de {@code source} vers {@code target}.
     *
     * @param force autorise l'écriture dans une cible déjà peuplée (sinon, refus : mélanger deux
     *              installations casserait la chaîne du journal d'audit)
     * @throws IllegalStateException si la cible contient déjà des données et que {@code force} est faux
     */
    public static Result copy(Database source, Database target, boolean force) throws SQLException {
        try (Connection from = source.connection(); Connection to = target.connection()) {
            if (!force) {
                String occupied = firstNonEmptyTable(to);
                if (occupied != null) {
                    throw new IllegalStateException("La base cible contient déjà des données (table \"" + occupied
                            + "\"). Utilisez une base vide, ou --force si vous savez ce que vous faites.");
                }
            }
            to.setAutoCommit(false);
            try {
                List<TableResult> results = new ArrayList<>();
                for (String table : TABLES) {
                    results.add(new TableResult(table, copyTable(from, to, table)));
                }
                to.commit();
                return new Result(List.copyOf(results));
            } catch (SQLException | RuntimeException e) {
                to.rollback();
                throw e;
            } finally {
                to.setAutoCommit(true);
            }
        }
    }

    private static String firstNonEmptyTable(Connection target) throws SQLException {
        for (String table : TABLES) {
            try (Statement statement = target.createStatement();
                 ResultSet rs = statement.executeQuery("SELECT COUNT(*) FROM " + table)) {
                if (rs.next() && rs.getInt(1) > 0) {
                    return table;
                }
            }
        }
        return null;
    }

    /** @return le nombre de lignes copiées */
    private static int copyTable(Connection from, Connection to, String table) throws SQLException {
        try (Statement select = from.createStatement();
             ResultSet rows = select.executeQuery("SELECT * FROM " + table)) {
            ResultSetMetaData meta = rows.getMetaData();
            int columnCount = meta.getColumnCount();
            List<String> columns = new ArrayList<>(columnCount);
            for (int i = 1; i <= columnCount; i++) {
                // Identifiants non cités : H2 les rend en majuscules, PostgreSQL les attend en minuscules.
                columns.add(meta.getColumnLabel(i).toLowerCase(Locale.ROOT));
            }
            String placeholders = String.join(", ", java.util.Collections.nCopies(columnCount, "?"));
            String sql = "INSERT INTO " + table + " (" + String.join(", ", columns) + ") VALUES (" + placeholders + ")";
            int copied = 0;
            try (PreparedStatement insert = to.prepareStatement(sql)) {
                while (rows.next()) {
                    for (int i = 1; i <= columnCount; i++) {
                        insert.setObject(i, rows.getObject(i));
                    }
                    insert.addBatch();
                    if (++copied % BATCH_SIZE == 0) {
                        insert.executeBatch();
                    }
                }
                insert.executeBatch();
            }
            LOG.info("Table {} : {} ligne(s) copiée(s)", table, copied);
            return copied;
        }
    }
}
