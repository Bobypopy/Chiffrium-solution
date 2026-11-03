package com.chiffrium.application.security;

import com.chiffrium.SecurityFixture;
import com.chiffrium.application.port.IdentityProvider;
import com.chiffrium.application.settings.Settings;
import com.chiffrium.domain.security.Role;
import com.chiffrium.domain.security.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SsoServiceTest {

    private static final String IP = "10.1.2.3";
    private static final String ISSUER = "https://idp.example.test";
    private static final String CODE = "code-autorisation";

    /** Fournisseur simulé : vérifie le code et le nonce comme le ferait un vrai fournisseur. */
    static final class FakeProvider implements IdentityProvider {
        Identity next = new Identity("sub-1", "alice", "Alice", "alice@example.test", List.of("crypto-admins"));
        String lastNonce;

        @Override
        public AuthorizationRequest authorizationRequest(Settings.Oidc config) {
            lastNonce = "nonce-" + System.nanoTime();
            return new AuthorizationRequest(ISSUER + "/authorize?state=s", "state-" + lastNonce, lastNonce, "verifier");
        }

        @Override
        public Identity exchange(Settings.Oidc config, String code, String codeVerifier, String expectedNonce) {
            if (!CODE.equals(code) || !expectedNonce.equals(lastNonce) || !"verifier".equals(codeVerifier)) {
                throw new AuthenticationException("Jeton ID invalide.");
            }
            return next;
        }
    }

    private SecurityFixture fx;
    private FakeProvider provider;
    private SsoService sso;
    private Actor admin;

    @BeforeEach
    void open(@TempDir Path dir) {
        fx = new SecurityFixture(dir);
        admin = fx.auth.authenticate(fx.setupAdmin(), IP).actor();
        provider = new FakeProvider();
        sso = new SsoService(provider, fx.userRepository, fx.auth, fx.settings, fx.audit, fx.clock);
    }

    @AfterEach
    void close() {
        fx.close();
    }

    private void enable(String adminGroup) {
        fx.settings.update(admin, new Settings(null, null, null, null, new Settings.Oidc(true, ISSUER, "client",
                "secret", "https://analyzer.example.test/api/auth/oidc/callback", Role.VIEWER, "groups", adminGroup,
                null)));
    }

    private String stateOfLastStart() {
        return "state-" + provider.lastNonce;
    }

    @Test
    void refusesWhenDisabled() {
        assertThatThrownBy(sso::start).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void provisionsTheAccountFromGroupsAndIssuesASingleUseTicket() {
        enable("crypto-admins");
        sso.start();
        String ticket = sso.complete(stateOfLastStart(), CODE, IP);

        AuthService.LoginResult login = sso.redeem(ticket);
        assertThat(login.user().source()).isEqualTo(User.Source.OIDC);
        assertThat(login.user().role()).isEqualTo(Role.ADMIN);
        assertThat(fx.auth.authenticate(login.token(), IP).user().username()).isEqualTo("alice");
        assertThatThrownBy(() -> sso.redeem(ticket)).isInstanceOf(AuthenticationException.class);

        // Retiré du groupe : rôle par défaut à la connexion suivante.
        provider.next = new IdentityProvider.Identity("sub-1", "alice", "Alice", null, List.of());
        sso.start();
        assertThat(sso.redeem(sso.complete(stateOfLastStart(), CODE, IP)).user().role()).isEqualTo(Role.VIEWER);
        assertThat(fx.audit.search(null, "SSO_USER_PROVISIONED", 10, 0)).hasSize(1);
    }

    @Test
    void stateIsSingleUseAndBoundToTheRequest() {
        enable(null);
        sso.start();
        String state = stateOfLastStart();
        assertThatThrownBy(() -> sso.complete("state-forge", CODE, IP)).isInstanceOf(AuthenticationException.class);
        sso.complete(state, CODE, IP);
        assertThatThrownBy(() -> sso.complete(state, CODE, IP)).isInstanceOf(AuthenticationException.class);
    }

    @Test
    void neverTakesOverALocalAccount() {
        enable(null);
        provider.next = new IdentityProvider.Identity("sub-9", SecurityFixture.ADMIN, "Imposteur", null, List.of());
        sso.start();
        assertThatThrownBy(() -> sso.complete(stateOfLastStart(), CODE, IP)).isInstanceOf(AccessDeniedException.class);
        assertThat(fx.audit.search(null, "SSO_LOGIN_FAILURE", 10, 0)).isNotEmpty();
    }

    @Test
    void derivesAUsernameFromTheSubjectWhenNoUsableNameIsProvided() {
        assertThat(SsoService.usernameFor(new IdentityProvider.Identity("AbC-123", null, null, null, List.of())))
                .isEqualTo("sso-abc123");
        assertThat(SsoService.usernameFor(new IdentityProvider.Identity("x", "Bob.Martin@Corp.test", null, null,
                List.of()))).isEqualTo("bob.martin@corp.test");
    }
}
