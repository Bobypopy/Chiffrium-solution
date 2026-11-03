package com.chiffrium.infrastructure.db;

import com.chiffrium.TestSupport;
import com.chiffrium.application.port.AuditRepository;
import com.chiffrium.application.security.Actor;
import com.chiffrium.application.security.AuditService;
import com.chiffrium.application.settings.Settings;
import com.chiffrium.domain.security.Group;
import com.chiffrium.domain.security.Role;
import com.chiffrium.domain.security.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.sql.Connection;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Mêmes dépôts sur un vrai PostgreSQL (migrations, insertion-ou-mise-à-jour, transactions).
 * Activé par {@code TEST_POSTGRES_URL} (ex. jdbc:postgresql://localhost:5432/test), {@code TEST_POSTGRES_USER}
 * et {@code TEST_POSTGRES_PASSWORD} : service PostgreSQL en CI, conteneur en local.
 */
@EnabledIfEnvironmentVariable(named = "TEST_POSTGRES_URL", matches = "jdbc:postgresql:.*")
class PostgresqlRepositoriesTest {

    private static Database freshDatabase() throws Exception {
        String url = System.getenv("TEST_POSTGRES_URL");
        String user = System.getenv("TEST_POSTGRES_USER");
        String password = System.getenv("TEST_POSTGRES_PASSWORD");
        Database bootstrap = Database.postgresql(url, user, password);
        try (Connection c = bootstrap.connection(); Statement st = c.createStatement()) {
            st.execute("DROP SCHEMA public CASCADE");
            st.execute("CREATE SCHEMA public");
        }
        bootstrap.close();
        return Database.postgresql(url, user, password);
    }

    @Test
    void repositoriesWorkOnPostgresql() throws Exception {
        try (Database db = freshDatabase()) {
            Instant now = Instant.parse("2026-01-01T00:00:00Z");
            JdbcUserRepository users = new JdbcUserRepository(db);
            User alice = new User(UUID.randomUUID().toString(), "alice", "Alice", null, Role.ANALYST, User.Source.LOCAL,
                    "hash", true, false, 0, null, now, null);
            users.save(alice);
            users.save(alice.withRole(Role.ADMIN));
            assertThat(users.findByUsername("alice")).get().extracting(User::role).isEqualTo(Role.ADMIN);
            assertThat(users.count()).isEqualTo(1);

            JdbcSettingsRepository settings = new JdbcSettingsRepository(db, TestSupport.cipher(), TestSupport.MAPPER);
            settings.save(Settings.defaults());
            settings.save(Settings.defaults());
            assertThat(settings.load()).isPresent();

            JdbcGroupRepository groups = new JdbcGroupRepository(db);
            Group team = new Group(UUID.randomUUID().toString(), "Équipe", null, Group.Visibility.PRIVATE, now, List.of());
            groups.save(team);
            groups.setMember(team.id(), alice.id(), false);
            groups.setMember(team.id(), alice.id(), true);
            assertThat(groups.membershipsOf(alice.id())).singleElement().extracting(Group.Membership::manager)
                    .isEqualTo(true);

            JdbcFavoriteRepository favorites = new JdbcFavoriteRepository(db, Clock.systemUTC());
            favorites.add(alice.id(), "a1");
            favorites.add(alice.id(), "a1");
            assertThat(favorites.analysisIds(alice.id())).containsExactly("a1");

            JdbcAuditRepository auditRepository = new JdbcAuditRepository(db);
            AuditService audit = new AuditService(auditRepository, Clock.systemUTC());
            audit.record(Actor.SYSTEM, "A", null, null);
            audit.record(Actor.SYSTEM, "B", null, null);
            var first = auditRepository.all().get(0);
            auditRepository.addAnchor(new AuditRepository.Anchor(first.sequence(), first.hash(), now, "test"));
            auditRepository.purgeUpTo(new AuditRepository.Checkpoint(first.sequence(), first.hash()));
            assertThat(audit.verify().intact()).isTrue();
            assertThat(auditRepository.all()).hasSize(1);
        }
    }
}
