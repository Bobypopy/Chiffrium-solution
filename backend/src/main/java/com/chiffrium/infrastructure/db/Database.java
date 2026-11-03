package com.chiffrium.infrastructure.db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Locale;

/**
 * Accès à la base : H2 embarquée chiffrée (défaut, bureau et petit serveur) ou PostgreSQL (serveur d'équipe).
 * Le schéma évolue par migrations numérotées ({@code db/migration/V<n>__<nom>.sql}), communes aux deux moteurs
 * grâce aux types substitués par le {@link Dialect}, appliquées une seule fois et tracées dans
 * {@code schema_version}.
 */
public final class Database implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(Database.class);
    private static final String MIGRATIONS_DIR = "/db/migration/";
    private static final List<String> MIGRATIONS = List.of("V1__security.sql", "V2__collaboration.sql",
            "V3__membership_notifications.sql");
    private static final int MAX_CONNECTIONS = 10;
    private static final String H2_USER = "chiffrium";
    private static final String POSTGRESQL_PREFIX = "jdbc:postgresql:";

    private final HikariDataSource pool;
    private final Dialect dialect;

    private Database(HikariConfig config, Dialect dialect) {
        config.setMaximumPoolSize(MAX_CONNECTIONS);
        config.setPoolName("chiffrium-" + dialect.name().toLowerCase(Locale.ROOT));
        this.pool = new HikariDataSource(config);
        this.dialect = dialect;
        migrate();
    }

    /**
     * Base H2 locale, fichier chiffré en AES.
     *
     * @param file         chemin de la base (sans extension)
     * @param filePassword mot de passe de chiffrement du fichier (dérivé de la clé maîtresse)
     * @param userPassword mot de passe du compte SQL (dérivé de la clé maîtresse)
     */
    public static Database h2(Path file, String filePassword, String userPassword) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:h2:file:" + file.toAbsolutePath() + ";CIPHER=AES;DB_CLOSE_ON_EXIT=FALSE");
        config.setUsername(H2_USER);
        // H2 : "motDePasseFichier motDePasseUtilisateur" (séparés par une espace).
        config.setPassword(filePassword + " " + userPassword);
        return new Database(config, Dialect.H2);
    }

    /**
     * Serveur PostgreSQL (chiffrement du transport à imposer dans l'URL, ex. {@code ?sslmode=verify-full}).
     */
    public static Database postgresql(String jdbcUrl, String user, String password) {
        if (!jdbcUrl.startsWith(POSTGRESQL_PREFIX)) {
            throw new IllegalArgumentException("DATABASE_URL doit commencer par " + POSTGRESQL_PREFIX);
        }
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(jdbcUrl);
        config.setUsername(user);
        config.setPassword(password);
        return new Database(config, Dialect.POSTGRESQL);
    }

    public Connection connection() throws SQLException {
        return pool.getConnection();
    }

    Dialect dialect() {
        return dialect;
    }

    private void migrate() {
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE IF NOT EXISTS schema_version (version INT PRIMARY KEY, name VARCHAR(200))");
            int current = 0;
            try (ResultSet rs = statement.executeQuery("SELECT COALESCE(MAX(version), 0) FROM schema_version")) {
                if (rs.next()) {
                    current = rs.getInt(1);
                }
            }
            for (int i = current; i < MIGRATIONS.size(); i++) {
                String name = MIGRATIONS.get(i);
                LOG.info("Migration de la base : {}", name);
                connection.setAutoCommit(false);
                // Commentaires retirés avant le découpage : un ";" dans un commentaire ne coupe pas l'instruction.
                for (String sql : stripComments(dialect.resolve(read(name))).split(";")) {
                    if (!sql.isBlank()) {
                        statement.execute(sql.strip());
                    }
                }
                try (PreparedStatement insert = connection.prepareStatement("INSERT INTO schema_version VALUES (?, ?)")) {
                    insert.setInt(1, i + 1);
                    insert.setString(2, name);
                    insert.executeUpdate();
                }
                connection.commit();
                connection.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Base de données inaccessible ou clé maîtresse incorrecte : " + e.getMessage(), e);
        }
    }

    private static String stripComments(String sql) {
        StringBuilder result = new StringBuilder();
        for (String line : sql.split("\n")) {
            if (!line.strip().startsWith("--")) {
                result.append(line).append('\n');
            }
        }
        return result.toString().strip();
    }

    private static String read(String name) {
        try (InputStream in = Database.class.getResourceAsStream(MIGRATIONS_DIR + name)) {
            if (in == null) {
                throw new IllegalStateException("Migration manquante : " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void close() {
        if (dialect == Dialect.H2) {
            try (Connection connection = connection(); Statement statement = connection.createStatement()) {
                statement.execute("SHUTDOWN");
            } catch (SQLException e) {
                LOG.debug("Arrêt de la base", e);
            }
        }
        pool.close();
    }
}
