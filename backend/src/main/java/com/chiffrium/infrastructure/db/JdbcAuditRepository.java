package com.chiffrium.infrastructure.db;

import com.chiffrium.application.port.AuditRepository;
import com.chiffrium.domain.security.AuditEvent;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.function.Function;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Journal d'audit en base : insertion uniquement, sauf la purge de rétention (entrées déjà exportées) qui
 * enregistre atomiquement un point de reprise.
 */
public final class JdbcAuditRepository implements AuditRepository {

    private static final int SINGLETON_ID = 1;

    private final Jdbc jdbc;

    public JdbcAuditRepository(Database database) {
        this.jdbc = new Jdbc(database);
    }

    @Override
    public void append(AuditEvent e) {
        try {
            jdbc.update("INSERT INTO audit_log (sequence, ts, actor, action, target, details, source_ip, "
                            + "previous_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    e.sequence(), e.timestamp().toString(), e.actor(), e.action(), e.target(), e.details(),
                    e.sourceIp(), e.previousHash(), e.hash());
        } catch (Jdbc.DuplicateKey duplicate) {
            // Une autre instance a écrit l'entrée no e.sequence() entre notre lecture et notre écriture.
            throw new SequenceTakenException("Numéro d'audit " + e.sequence() + " déjà pris", duplicate);
        }
    }

    @Override
    public AuditEvent appendChained(Function<Optional<AuditEvent>, AuditEvent> builder) {
        try {
            return jdbc.inTransaction(connection -> {
                // "FOR UPDATE" sur la dernière entrée : une autre instance attend ici au lieu d'écrire le
                // même numéro (H2 et PostgreSQL). Le verrou tient jusqu'au commit, insertion comprise.
                Optional<AuditEvent> previous = lockLast(connection);
                AuditEvent event = builder.apply(previous);
                insert(connection, event);
                return event;
            });
        } catch (Jdbc.DuplicateKey duplicate) {
            throw new SequenceTakenException("Numéro d'audit déjà pris", duplicate);
        }
    }

    private static Optional<AuditEvent> lockLast(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT * FROM audit_log ORDER BY sequence DESC LIMIT 1 FOR UPDATE");
             ResultSet rs = statement.executeQuery()) {
            return rs.next() ? Optional.of(map(rs)) : Optional.empty();
        }
    }

    private static void insert(Connection connection, AuditEvent e) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO audit_log (sequence, ts, actor, action, target, details, source_ip, previous_hash, hash) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            statement.setLong(1, e.sequence());
            statement.setString(2, e.timestamp().toString());
            statement.setString(3, e.actor());
            statement.setString(4, e.action());
            statement.setString(5, e.target());
            statement.setString(6, e.details());
            statement.setString(7, e.sourceIp());
            statement.setString(8, e.previousHash());
            statement.setString(9, e.hash());
            statement.executeUpdate();
        }
    }

    @Override
    public Optional<AuditEvent> last() {
        return jdbc.queryOne("SELECT * FROM audit_log ORDER BY sequence DESC LIMIT 1", JdbcAuditRepository::map);
    }

    @Override
    public List<AuditEvent> search(String actor, String action, int limit, int offset) {
        StringBuilder sql = new StringBuilder("SELECT * FROM audit_log WHERE 1 = 1");
        List<Object> parameters = new ArrayList<>();
        if (actor != null) {
            sql.append(" AND actor = ?");
            parameters.add(actor);
        }
        if (action != null) {
            sql.append(" AND action = ?");
            parameters.add(action);
        }
        sql.append(" ORDER BY sequence DESC LIMIT ? OFFSET ?");
        parameters.add(limit);
        parameters.add(offset);
        return jdbc.query(sql.toString(), JdbcAuditRepository::map, parameters.toArray());
    }

    @Override
    public List<AuditEvent> all() {
        return jdbc.query("SELECT * FROM audit_log ORDER BY sequence", JdbcAuditRepository::map);
    }

    @Override
    public List<AuditEvent> after(long sequence, int limit) {
        return jdbc.query("SELECT * FROM audit_log WHERE sequence > ? ORDER BY sequence LIMIT ?",
                JdbcAuditRepository::map, sequence, limit);
    }

    @Override
    public Optional<Checkpoint> checkpoint() {
        return jdbc.queryOne("SELECT sequence, hash FROM audit_checkpoint WHERE id = ?",
                rs -> new Checkpoint(rs.getLong(1), rs.getString(2)), SINGLETON_ID);
    }

    @Override
    public void purgeUpTo(Checkpoint upTo) {
        jdbc.transaction(List.of(
                new Jdbc.Sql("DELETE FROM audit_log WHERE sequence <= ?", upTo.sequence()),
                new Jdbc.Sql(jdbc.upsertSql("audit_checkpoint", "id", "id, sequence, hash"), SINGLETON_ID,
                        upTo.sequence(), upTo.hash())));
    }

    @Override
    public void addAnchor(Anchor anchor) {
        jdbc.upsert("audit_anchors", "sequence", "sequence, hash, exported_at, target", anchor.sequence(),
                anchor.hash(), anchor.exportedAt(), anchor.target());
    }

    @Override
    public Optional<Anchor> lastAnchor() {
        return jdbc.queryOne("SELECT * FROM audit_anchors ORDER BY sequence DESC LIMIT 1", rs -> new Anchor(
                rs.getLong("sequence"), rs.getString("hash"), Jdbc.instant(rs, "exported_at"), rs.getString("target")));
    }

    private static AuditEvent map(ResultSet rs) throws SQLException {
        return new AuditEvent(rs.getLong("sequence"), Instant.parse(rs.getString("ts")), rs.getString("actor"),
                rs.getString("action"), rs.getString("target"), rs.getString("details"), rs.getString("source_ip"),
                rs.getString("previous_hash"), rs.getString("hash"));
    }
}
