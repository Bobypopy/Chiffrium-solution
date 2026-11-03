package com.chiffrium.infrastructure.db;

import com.chiffrium.application.port.UserRepository;
import com.chiffrium.domain.security.Role;
import com.chiffrium.domain.security.User;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Comptes utilisateurs en base.
 */
public final class JdbcUserRepository implements UserRepository {

    private static final String COLUMNS = "id, username, display_name, email, role, source, password_hash, enabled, "
            + "must_change_password, failed_attempts, locked_until, created_at, last_login_at";

    private final Jdbc jdbc;

    public JdbcUserRepository(Database database) {
        this.jdbc = new Jdbc(database);
    }

    @Override
    public Optional<User> findByUsername(String username) {
        return jdbc.queryOne("SELECT " + COLUMNS + " FROM users WHERE username = ?", JdbcUserRepository::map,
                User.normalizeUsername(username));
    }

    @Override
    public Optional<User> findById(String id) {
        return jdbc.queryOne("SELECT " + COLUMNS + " FROM users WHERE id = ?", JdbcUserRepository::map, id);
    }

    @Override
    public List<User> findAll() {
        return jdbc.query("SELECT " + COLUMNS + " FROM users ORDER BY username", JdbcUserRepository::map);
    }

    @Override
    public long count() {
        return jdbc.queryOne("SELECT COUNT(*) FROM users", rs -> rs.getLong(1)).orElse(0L);
    }

    @Override
    public void save(User u) {
        jdbc.upsert("users", "id", COLUMNS,
                u.id(), u.username(), u.displayName(), u.email(), u.role().name(), u.source().name(), u.passwordHash(),
                u.enabled(), u.mustChangePassword(), u.failedAttempts(), u.lockedUntil(), u.createdAt(),
                u.lastLoginAt());
    }

    private static User map(ResultSet rs) throws SQLException {
        return new User(
                rs.getString("id"),
                rs.getString("username"),
                rs.getString("display_name"),
                rs.getString("email"),
                Role.valueOf(rs.getString("role")),
                User.Source.valueOf(rs.getString("source").toUpperCase(Locale.ROOT)),
                rs.getString("password_hash"),
                rs.getBoolean("enabled"),
                rs.getBoolean("must_change_password"),
                rs.getInt("failed_attempts"),
                Jdbc.instant(rs, "locked_until"),
                Jdbc.instant(rs, "created_at"),
                Jdbc.instant(rs, "last_login_at"));
    }
}
