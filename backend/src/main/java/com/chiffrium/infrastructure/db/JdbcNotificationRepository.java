package com.chiffrium.infrastructure.db;

import com.chiffrium.application.port.NotificationRepository;
import com.chiffrium.domain.security.Notification;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Notifications en base.
 */
public final class JdbcNotificationRepository implements NotificationRepository {

    private final Jdbc jdbc;

    public JdbcNotificationRepository(Database database) {
        this.jdbc = new Jdbc(database);
    }

    @Override
    public void save(Notification n) {
        jdbc.upsert("notifications", "id", "id, user_id, kind, title, body, link, created_at, read_at", n.id(),
                n.userId(), n.kind(), n.title(), n.body(), n.link(), n.createdAt(), n.readAt());
    }

    @Override
    public List<Notification> forUser(String userId, boolean unreadOnly, int limit) {
        return jdbc.query("SELECT * FROM notifications WHERE user_id = ?" + (unreadOnly ? " AND read_at IS NULL" : "")
                + " ORDER BY created_at DESC LIMIT ?", JdbcNotificationRepository::map, userId, limit);
    }

    @Override
    public long unreadCount(String userId) {
        return jdbc.queryOne("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL",
                rs -> rs.getLong(1), userId).orElse(0L);
    }

    @Override
    public void markRead(String userId, List<String> ids, Instant now) {
        if (ids.isEmpty()) {
            jdbc.update("UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL", now, userId);
            return;
        }
        List<Jdbc.Sql> updates = new ArrayList<>();
        for (String id : ids) {
            updates.add(new Jdbc.Sql("UPDATE notifications SET read_at = ? WHERE id = ? AND user_id = ? AND read_at IS NULL",
                    now, id, userId));
        }
        jdbc.transaction(updates);
    }

    @Override
    public int purgeReadBefore(Instant limit) {
        return jdbc.update("DELETE FROM notifications WHERE read_at IS NOT NULL AND read_at < ?", limit);
    }

    private static Notification map(ResultSet rs) throws SQLException {
        return new Notification(rs.getString("id"), rs.getString("user_id"), rs.getString("kind"), rs.getString("title"),
                rs.getString("body"), rs.getString("link"), Jdbc.instant(rs, "created_at"), Jdbc.instant(rs, "read_at"));
    }
}
