package com.chiffrium.infrastructure.db;

import com.chiffrium.application.port.SessionRepository;

import java.time.Instant;
import java.util.Optional;

/**
 * Sessions en base (seule l'empreinte du jeton est conservée).
 */
public final class JdbcSessionRepository implements SessionRepository {

    private final Jdbc jdbc;

    public JdbcSessionRepository(Database database) {
        this.jdbc = new Jdbc(database);
    }

    @Override
    public void create(Session s) {
        jdbc.update("INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at, source_ip) "
                + "VALUES (?, ?, ?, ?, ?, ?)", s.tokenHash(), s.userId(), s.createdAt(), s.lastSeenAt(), s.expiresAt(),
                s.sourceIp());
    }

    @Override
    public Optional<Session> findByTokenHash(String tokenHash) {
        return jdbc.queryOne("SELECT * FROM sessions WHERE token_hash = ?", rs -> new Session(
                rs.getString("token_hash"), rs.getString("user_id"), Jdbc.instant(rs, "created_at"),
                Jdbc.instant(rs, "last_seen_at"), Jdbc.instant(rs, "expires_at"), rs.getString("source_ip")), tokenHash);
    }

    @Override
    public void touch(String tokenHash, Instant lastSeenAt) {
        jdbc.update("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", lastSeenAt, tokenHash);
    }

    @Override
    public void delete(String tokenHash) {
        jdbc.update("DELETE FROM sessions WHERE token_hash = ?", tokenHash);
    }

    @Override
    public void deleteByUser(String userId) {
        jdbc.update("DELETE FROM sessions WHERE user_id = ?", userId);
    }

    @Override
    public int deleteExpired(Instant now) {
        return jdbc.update("DELETE FROM sessions WHERE expires_at < ?", now);
    }
}
