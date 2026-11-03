package com.chiffrium.infrastructure.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Accès JDBC minimal et sûr : requêtes toujours paramétrées (aucune concaténation de valeurs -> pas
 * d'injection SQL), ressources fermées automatiquement, erreurs converties en exceptions non vérifiées.
 */
final class Jdbc {

    /** Transforme la ligne courante en objet. */
    @FunctionalInterface
    interface RowMapper<T> {
        T map(ResultSet rs) throws SQLException;
    }

    private final Database database;

    Jdbc(Database database) {
        this.database = database;
    }

    /** Doublon sur une contrainte d'unicité : l'appelant peut réessayer avec une autre valeur. */
    static final class DuplicateKey extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        DuplicateKey(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Code SQL standard des violations de contrainte (classe 23) : doublon, clé étrangère, non nul. */
    private static boolean isDuplicate(SQLException e) {
        return e instanceof SQLIntegrityConstraintViolationException
                || (e.getSQLState() != null && e.getSQLState().startsWith("23"));
    }

    int update(String sql, Object... parameters) {
        try (Connection connection = database.connection();
             PreparedStatement statement = prepare(connection, sql, parameters)) {
            return statement.executeUpdate();
        } catch (SQLException e) {
            if (isDuplicate(e)) {
                throw new DuplicateKey("Doublon : " + e.getMessage(), e);
            }
            throw new IllegalStateException("Erreur SQL : " + e.getMessage(), e);
        }
    }

    /** Travail transactionnel ayant besoin de la connexion (verrou de ligne, lecture puis écriture). */
    @FunctionalInterface
    interface TransactionalWork<T> {
        T run(Connection connection) throws SQLException;
    }

    /** Exécute un travail dans une transaction ; les verrous posés tiennent jusqu'au commit. */
    <T> T inTransaction(TransactionalWork<T> work) {
        try (Connection connection = database.connection()) {
            connection.setAutoCommit(false);
            try {
                T result = work.run(connection);
                connection.commit();
                return result;
            } catch (SQLException | RuntimeException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException e) {
            if (isDuplicate(e)) {
                throw new DuplicateKey("Doublon : " + e.getMessage(), e);
            }
            throw new IllegalStateException("Erreur SQL : " + e.getMessage(), e);
        }
    }

    /** Requête paramétrée d'un lot transactionnel. */
    record Sql(String sql, Object... parameters) {
    }

    /** Exécute plusieurs mises à jour atomiquement (tout ou rien). */
    void transaction(List<Sql> statements) {
        try (Connection connection = database.connection()) {
            connection.setAutoCommit(false);
            try {
                for (Sql statement : statements) {
                    try (PreparedStatement prepared = prepare(connection, statement.sql(), statement.parameters())) {
                        prepared.executeUpdate();
                    }
                }
                connection.commit();
            } catch (SQLException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Erreur SQL : " + e.getMessage(), e);
        }
    }

    /** Requête d'insertion ou de mise à jour selon la clé, dans la syntaxe du moteur. */
    String upsertSql(String table, String keyColumns, String columns) {
        return database.dialect().upsert(table, Dialect.columns(keyColumns), Dialect.columns(columns));
    }

    /** Insertion ou mise à jour selon la clé, dans la syntaxe du moteur. */
    int upsert(String table, String keyColumns, String columns, Object... parameters) {
        return update(upsertSql(table, keyColumns, columns), parameters);
    }

    <T> List<T> query(String sql, RowMapper<T> mapper, Object... parameters) {
        try (Connection connection = database.connection();
             PreparedStatement statement = prepare(connection, sql, parameters);
             ResultSet rs = statement.executeQuery()) {
            List<T> result = new ArrayList<>();
            while (rs.next()) {
                result.add(mapper.map(rs));
            }
            return result;
        } catch (SQLException e) {
            throw new IllegalStateException("Erreur SQL : " + e.getMessage(), e);
        }
    }

    <T> Optional<T> queryOne(String sql, RowMapper<T> mapper, Object... parameters) {
        return query(sql, mapper, parameters).stream().findFirst();
    }

    private static PreparedStatement prepare(Connection connection, String sql, Object... parameters) throws SQLException {
        PreparedStatement statement = connection.prepareStatement(sql);
        for (int i = 0; i < parameters.length; i++) {
            Object value = parameters[i];
            statement.setObject(i + 1, value instanceof Instant instant ? Timestamp.from(instant) : value);
        }
        return statement;
    }

    static Instant instant(ResultSet rs, String column) throws SQLException {
        Timestamp timestamp = rs.getTimestamp(column);
        return timestamp == null ? null : timestamp.toInstant();
    }
}
