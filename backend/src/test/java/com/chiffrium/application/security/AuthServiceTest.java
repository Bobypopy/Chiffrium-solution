package com.chiffrium.application.security;

import com.chiffrium.SecurityFixture;
import com.chiffrium.application.security.AuthService.AuthenticatedSession;
import com.chiffrium.application.security.UserService.UserWithPassword;
import com.chiffrium.domain.security.AuditEvent;
import com.chiffrium.domain.security.Role;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthServiceTest {

    private static final String IP = "10.0.0.1";
    private SecurityFixture fx;

    @BeforeEach
    void open(@TempDir Path dir) {
        fx = new SecurityFixture(dir);
    }

    @AfterEach
    void close() {
        fx.close();
    }

    @Test
    void setupRequiresTheInstallationTokenAndHappensOnce() {
        assertThat(fx.auth.setupRequired()).isTrue();
        assertThatThrownBy(() -> fx.auth.setup("mauvais", "admin", SecurityFixture.ADMIN_PASSWORD.clone(), null, IP))
                .isInstanceOf(AuthenticationException.class);

        String token = fx.setupAdmin();
        assertThat(fx.auth.authenticate(token, IP).actor().role()).isEqualTo(Role.ADMIN);
        assertThat(fx.auth.setupRequired()).isFalse();
        assertThatThrownBy(fx::setupAdmin).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void rejectsWeakPasswords() {
        assertThatThrownBy(() -> fx.auth.setup(SecurityFixture.SETUP_TOKEN, "admin", "court".toCharArray(), null, IP))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("caractères");
        assertThatThrownBy(() -> fx.auth.setup(SecurityFixture.SETUP_TOKEN, "admin",
                "admin-est-mon-secret".toCharArray(), null, IP))
                .hasMessageContaining("identifiant");
    }

    @Test
    void locksTheAccountAfterRepeatedFailures() {
        fx.setupAdmin();
        for (int i = 0; i < AuthService.MAX_FAILED_ATTEMPTS; i++) {
            assertThatThrownBy(() -> fx.auth.login("admin", "mauvais mot de passe".toCharArray(), IP))
                    .isInstanceOf(AuthenticationException.class);
        }
        assertThatThrownBy(() -> fx.auth.login("admin", SecurityFixture.ADMIN_PASSWORD.clone(), IP))
                .hasMessageContaining("verrouillé");

        fx.clock.advance(AuthService.LOCK_DURATION.plusSeconds(1));
        assertThat(fx.auth.login("admin", SecurityFixture.ADMIN_PASSWORD.clone(), IP).token()).isNotBlank();
        assertThat(fx.audit.search(null, "ACCOUNT_LOCKED", 10, 0)).hasSize(1);
    }

    @Test
    void unknownUserGetsTheSameGenericMessage() {
        fx.setupAdmin();
        assertThatThrownBy(() -> fx.auth.login("inconnu", "peu importe ici".toCharArray(), IP))
                .hasMessage(AuthService.GENERIC_FAILURE);
        assertThatThrownBy(() -> fx.auth.login("admin", "mauvais mot de passe".toCharArray(), IP))
                .hasMessage(AuthService.GENERIC_FAILURE);
    }

    @Test
    void sessionsExpireAfterInactivityAndOnLogout() {
        String token = fx.setupAdmin();
        fx.clock.advance(Duration.ofMinutes(fx.settings.current().sessions().idleMinutes() + 1L));
        assertThatThrownBy(() -> fx.auth.authenticate(token, IP)).isInstanceOf(AuthenticationException.class);

        String second = fx.auth.login("admin", SecurityFixture.ADMIN_PASSWORD.clone(), IP).token();
        AuthenticatedSession session = fx.auth.authenticate(second, IP);
        fx.auth.logout(second, session.actor());
        assertThatThrownBy(() -> fx.auth.authenticate(second, IP)).isInstanceOf(AuthenticationException.class);
        assertThatThrownBy(() -> fx.auth.authenticate(null, IP)).isInstanceOf(AuthenticationException.class);
    }

    @Test
    void temporaryPasswordMustBeChangedAndOldSessionsAreClosed() {
        Actor admin = fx.auth.authenticate(fx.setupAdmin(), IP).actor();
        UserWithPassword created = fx.users.create(admin, "alice", "Alice", null, Role.ANALYST);
        assertThat(created.user().mustChangePassword()).isTrue();

        String token = fx.auth.login("alice", created.temporaryPassword().toCharArray(), IP).token();
        AuthenticatedSession alice = fx.auth.authenticate(token, IP);
        String renewed = fx.auth.changePassword(alice.actor(), created.temporaryPassword().toCharArray(),
                "nouvelle phrase secrète".toCharArray()).token();

        assertThatThrownBy(() -> fx.auth.authenticate(token, IP)).isInstanceOf(AuthenticationException.class);
        assertThat(fx.auth.authenticate(renewed, IP).user().mustChangePassword()).isFalse();
    }

    @Test
    void enforcesRolesAndKeepsAtLeastOneAdmin() {
        Actor admin = fx.auth.authenticate(fx.setupAdmin(), IP).actor();
        UserWithPassword viewer = fx.users.create(admin, "bob", null, null, Role.VIEWER);
        Actor bob = new Actor(viewer.user().id(), "bob", Role.VIEWER, IP);

        assertThatThrownBy(() -> fx.users.list(bob)).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> fx.users.update(admin, admin.userId(), Role.VIEWER, null, null, null))
                .hasMessageContaining("administrateur");
        assertThatThrownBy(() -> fx.users.update(admin, admin.userId(), null, false, null, null))
                .hasMessageContaining("propre compte");

        fx.users.update(admin, viewer.user().id(), null, false, null, null);
        assertThatThrownBy(() -> fx.auth.login("bob", viewer.temporaryPassword().toCharArray(), IP))
                .isInstanceOf(AuthenticationException.class);
    }

    @Test
    void everySecurityEventIsAuditedInAnIntactChain() {
        Actor admin = fx.auth.authenticate(fx.setupAdmin(), IP).actor();
        fx.users.create(admin, "carol", null, null, Role.ANALYST);
        assertThatThrownBy(() -> fx.auth.login("carol", "mauvais mot de passe".toCharArray(), IP))
                .isInstanceOf(AuthenticationException.class);

        assertThat(fx.audit.all()).extracting(AuditEvent::action)
                .containsSubsequence("SETUP_COMPLETED", "USER_CREATED", "LOGIN_FAILURE");
        assertThat(fx.audit.all()).allSatisfy(e -> assertThat(e.details()).doesNotContain("mauvais"));
        assertThat(fx.audit.verify().intact()).isTrue();
    }
}
