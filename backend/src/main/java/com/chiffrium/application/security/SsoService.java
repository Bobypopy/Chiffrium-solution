package com.chiffrium.application.security;

import com.chiffrium.application.port.IdentityProvider;
import com.chiffrium.application.port.IdentityProvider.AuthorizationRequest;
import com.chiffrium.application.port.IdentityProvider.Identity;
import com.chiffrium.application.port.UserRepository;
import com.chiffrium.application.security.AuthService.LoginResult;
import com.chiffrium.application.settings.Settings;
import com.chiffrium.application.settings.SettingsService;
import com.chiffrium.domain.security.Role;
import com.chiffrium.domain.security.User;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Authentification unique OpenID Connect (flux "authorization code" + PKCE).
 *
 * <ol>
 *   <li>{@link #start()} : URL du fournisseur ; state, nonce et vérificateur PKCE restent côté serveur ;</li>
 *   <li>{@link #complete} : au retour, le code est échangé et le jeton ID vérifié, le compte est créé ou mis à
 *       jour (rôle déduit des groupes) puis un ticket à usage unique est émis ;</li>
 *   <li>{@link #redeem} : l'interface échange le ticket contre une session (le jeton de session ne transite
 *       jamais dans une URL).</li>
 * </ol>
 * Un compte local existant n'est jamais rattaché à une identité SSO (pas de prise de contrôle de compte).
 */
public final class SsoService {

    static final Duration PENDING_TTL = Duration.ofMinutes(10);
    static final Duration TICKET_TTL = Duration.ofSeconds(60);
    /** Plafond des demandes en attente : borne la mémoire face à un afflux de requêtes /start. */
    static final int MAX_PENDING = 1_000;
    private static final int TICKET_BYTES = 32;
    private static final int MAX_USERNAME_LENGTH = 64;
    private static final String SSO_PREFIX = "sso-";

    private record Pending(String nonce, String codeVerifier, Instant createdAt) {
    }

    private record Ticket(LoginResult login, Instant createdAt) {
    }

    private final IdentityProvider provider;
    private final UserRepository users;
    private final AuthService auth;
    private final SettingsService settings;
    private final AuditService audit;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final Map<String, Ticket> tickets = new ConcurrentHashMap<>();

    public SsoService(IdentityProvider provider, UserRepository users, AuthService auth, SettingsService settings,
                      AuditService audit, Clock clock) {
        this.provider = provider;
        this.users = users;
        this.auth = auth;
        this.settings = settings;
        this.audit = audit;
        this.clock = clock;
    }

    public boolean enabled() {
        return settings.current().oidc().enabled();
    }

    /** @return l'URL du fournisseur d'identité vers laquelle rediriger le navigateur */
    public String start() {
        Settings.Oidc config = requireEnabled();
        purgeExpired();
        if (pending.size() >= MAX_PENDING) {
            throw new AuthenticationException("Trop de connexions SSO en cours, réessayer dans quelques minutes.");
        }
        AuthorizationRequest request = provider.authorizationRequest(config);
        pending.put(request.state(), new Pending(request.nonce(), request.codeVerifier(), clock.instant()));
        return request.url();
    }

    /**
     * Termine la connexion au retour du fournisseur.
     *
     * @return ticket à usage unique, valable {@link #TICKET_TTL}
     */
    public String complete(String state, String code, String sourceIp) {
        Settings.Oidc config = requireEnabled();
        Pending request = state == null ? null : pending.remove(state);
        if (request == null || request.createdAt().plus(PENDING_TTL).isBefore(clock.instant()) || code == null) {
            audit.record(AuthService.anonymous(sourceIp), "SSO_LOGIN_FAILURE", null,
                    "state inconnu, expiré ou code absent");
            throw new AuthenticationException("Connexion SSO expirée ou invalide, recommencer.");
        }
        Identity identity;
        try {
            identity = provider.exchange(config, code, request.codeVerifier(), request.nonce());
        } catch (AuthenticationException e) {
            audit.record(AuthService.anonymous(sourceIp), "SSO_LOGIN_FAILURE", null, e.getMessage());
            throw e;
        }
        User user = provision(config, identity, sourceIp);
        LoginResult login = auth.openSession(user, sourceIp);
        audit.record(new Actor(user.id(), user.username(), user.role(), sourceIp), "SSO_LOGIN_SUCCESS",
                user.username(), "rôle " + user.role().id());
        String ticket = newTicket();
        tickets.put(ticket, new Ticket(login, clock.instant()));
        return ticket;
    }

    /** Échange un ticket (une seule fois) contre la session ouverte. */
    public LoginResult redeem(String ticket) {
        Ticket found = ticket == null ? null : tickets.remove(ticket);
        if (found == null || found.createdAt().plus(TICKET_TTL).isBefore(clock.instant())) {
            throw new AuthenticationException("Ticket SSO invalide ou expiré.");
        }
        return found.login();
    }

    private User provision(Settings.Oidc config, Identity identity, String sourceIp) {
        String username = usernameFor(identity);
        Optional<Role> mapped = mappedRole(config, identity);
        Instant now = clock.instant();
        Optional<User> existing = users.findByUsername(username);
        if (existing.isPresent()) {
            User user = existing.get();
            if (user.source() != User.Source.OIDC) {
                audit.record(AuthService.anonymous(sourceIp), "SSO_LOGIN_FAILURE", username,
                        "identifiant déjà utilisé par un compte local");
                throw new AccessDeniedException("Un compte local porte déjà cet identifiant : contacter un administrateur.");
            }
            if (!user.enabled()) {
                audit.record(AuthService.anonymous(sourceIp), "SSO_LOGIN_FAILURE", username, "compte désactivé");
                throw new AuthenticationException("Compte désactivé.");
            }
            User updated = user.withProfile(orElse(identity.displayName(), user.displayName()),
                    orElse(identity.email(), user.email())).withSuccessfulLogin(now);
            if (mapped.isPresent() && mapped.get() != user.role()) {
                audit.record(Actor.SYSTEM, "USER_ROLE_CHANGED", username,
                        user.role().id() + " -> " + mapped.get().id() + " (groupes SSO)");
                updated = updated.withRole(mapped.get());
            }
            users.save(updated);
            return updated;
        }
        Role role = mapped.orElse(config.defaultRole() == null ? Role.VIEWER : config.defaultRole());
        User created = new User(UUID.randomUUID().toString(), username, orElse(identity.displayName(), username),
                identity.email(), role, User.Source.OIDC, null, true, false, 0, null, now, now);
        users.save(created);
        audit.record(Actor.SYSTEM, "SSO_USER_PROVISIONED", username, "rôle " + role.id());
        return created;
    }

    /** Rôle imposé par les groupes, uniquement si des groupes sont configurés (sinon le rôle est géré à la main). */
    static Optional<Role> mappedRole(Settings.Oidc config, Identity identity) {
        if (config.adminGroup() == null && config.analystGroup() == null) {
            return Optional.empty();
        }
        if (config.adminGroup() != null && identity.groups().contains(config.adminGroup())) {
            return Optional.of(Role.ADMIN);
        }
        if (config.analystGroup() != null && identity.groups().contains(config.analystGroup())) {
            return Optional.of(Role.ANALYST);
        }
        return Optional.of(config.defaultRole() == null ? Role.VIEWER : config.defaultRole());
    }

    static String usernameFor(Identity identity) {
        String candidate = identity.username() != null ? identity.username() : identity.email();
        String normalized = User.normalizeUsername(candidate);
        if (normalized == null || !normalized.matches("[a-z0-9][a-z0-9._@-]{2,63}")) {
            String subject = identity.subject().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
            normalized = SSO_PREFIX + subject.substring(0, Math.min(subject.length(), MAX_USERNAME_LENGTH - SSO_PREFIX.length()));
        }
        return normalized;
    }

    private Settings.Oidc requireEnabled() {
        Settings.Oidc config = settings.current().oidc();
        if (!config.enabled()) {
            throw new AccessDeniedException("L'authentification unique n'est pas activée.");
        }
        return config;
    }

    private void purgeExpired() {
        Instant now = clock.instant();
        pending.values().removeIf(p -> p.createdAt().plus(PENDING_TTL).isBefore(now));
        tickets.values().removeIf(t -> t.createdAt().plus(TICKET_TTL).isBefore(now));
    }

    private String newTicket() {
        byte[] bytes = new byte[TICKET_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String orElse(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
