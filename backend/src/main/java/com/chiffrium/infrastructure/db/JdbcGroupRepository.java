package com.chiffrium.infrastructure.db;

import com.chiffrium.application.port.GroupRepository;
import com.chiffrium.domain.security.Group;
import com.chiffrium.domain.security.GroupInvitation;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

/**
 * Groupes, appartenances et propositions d'adhésion en base.
 */
public final class JdbcGroupRepository implements GroupRepository {

    private static final String MEMBERS_SQL = "SELECT m.user_id, u.username, u.display_name, m.manager "
            + "FROM group_members m JOIN users u ON u.id = m.user_id WHERE m.group_id = ? ORDER BY u.username";
    private static final String INVITATION_SQL = "SELECT i.*, g.name AS group_name, u.username FROM group_invitations i "
            + "JOIN user_groups g ON g.id = i.group_id JOIN users u ON u.id = i.user_id ";
    private static final String INVITATION_COLUMNS = "id, group_id, user_id, kind, manager, message, created_by, "
            + "status, responded_by, created_at, responded_at";
    private static final String PENDING = "PENDING";

    private final Jdbc jdbc;

    public JdbcGroupRepository(Database database) {
        this.jdbc = new Jdbc(database);
    }

    @Override
    public List<Group> findAll() {
        return jdbc.query("SELECT * FROM user_groups ORDER BY name", JdbcGroupRepository::header).stream()
                .map(this::withMembers)
                .toList();
    }

    @Override
    public Optional<Group> findById(String id) {
        return jdbc.queryOne("SELECT * FROM user_groups WHERE id = ?", JdbcGroupRepository::header, id)
                .map(this::withMembers);
    }

    @Override
    public Optional<Group> findByName(String name) {
        return jdbc.queryOne("SELECT * FROM user_groups WHERE LOWER(name) = LOWER(?)", JdbcGroupRepository::header, name)
                .map(this::withMembers);
    }

    @Override
    public void save(Group group) {
        jdbc.upsert("user_groups", "id", "id, name, description, visibility, created_at", group.id(), group.name(),
                group.description(), group.visibility().name(), group.createdAt());
    }

    @Override
    public void delete(String id) {
        jdbc.update("DELETE FROM user_groups WHERE id = ?", id);
    }

    @Override
    public void setMember(String groupId, String userId, boolean manager) {
        jdbc.upsert("group_members", "group_id, user_id", "group_id, user_id, manager", groupId, userId, manager);
    }

    @Override
    public void removeMember(String groupId, String userId) {
        jdbc.update("DELETE FROM group_members WHERE group_id = ? AND user_id = ?", groupId, userId);
    }

    @Override
    public List<Group.Membership> membershipsOf(String userId) {
        return jdbc.query("SELECT g.id, g.name, m.manager FROM group_members m JOIN user_groups g ON g.id = m.group_id "
                        + "WHERE m.user_id = ? ORDER BY g.name",
                rs -> new Group.Membership(rs.getString(1), rs.getString(2), rs.getBoolean(3)), userId);
    }

    @Override
    public void saveInvitation(GroupInvitation i) {
        jdbc.upsert("group_invitations", "id", INVITATION_COLUMNS, i.id(), i.groupId(), i.userId(), i.kind().name(),
                i.manager(), i.message(), i.createdBy(), i.status().name(), i.respondedBy(), i.createdAt(),
                i.respondedAt());
    }

    @Override
    public Optional<GroupInvitation> findInvitation(String id) {
        return jdbc.queryOne(INVITATION_SQL + "WHERE i.id = ?", JdbcGroupRepository::invitation, id);
    }

    @Override
    public List<GroupInvitation> pendingForUser(String userId) {
        return jdbc.query(INVITATION_SQL + "WHERE i.user_id = ? AND i.status = ? ORDER BY i.created_at DESC",
                JdbcGroupRepository::invitation, userId, PENDING);
    }

    @Override
    public List<GroupInvitation> pendingForGroup(String groupId) {
        return jdbc.query(INVITATION_SQL + "WHERE i.group_id = ? AND i.status = ? ORDER BY i.created_at DESC",
                JdbcGroupRepository::invitation, groupId, PENDING);
    }

    private Group withMembers(Group header) {
        List<Group.Member> members = jdbc.query(MEMBERS_SQL,
                rs -> new Group.Member(rs.getString(1), rs.getString(2), rs.getString(3), rs.getBoolean(4)), header.id());
        return new Group(header.id(), header.name(), header.description(), header.visibility(), header.createdAt(),
                members);
    }

    private static Group header(ResultSet rs) throws SQLException {
        return new Group(rs.getString("id"), rs.getString("name"), rs.getString("description"),
                Group.Visibility.valueOf(rs.getString("visibility")), Jdbc.instant(rs, "created_at"), List.of());
    }

    private static GroupInvitation invitation(ResultSet rs) throws SQLException {
        return new GroupInvitation(rs.getString("id"), rs.getString("group_id"), rs.getString("group_name"),
                rs.getString("user_id"), rs.getString("username"), GroupInvitation.Kind.valueOf(rs.getString("kind")),
                rs.getBoolean("manager"), rs.getString("message"), rs.getString("created_by"),
                GroupInvitation.Status.valueOf(rs.getString("status")), rs.getString("responded_by"),
                Jdbc.instant(rs, "created_at"), Jdbc.instant(rs, "responded_at"));
    }
}
