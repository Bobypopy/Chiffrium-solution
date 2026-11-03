package com.chiffrium.application.security;

import com.chiffrium.application.port.PasswordHasher;
import com.chiffrium.application.port.SessionRepository;
import com.chiffrium.application.port.SessionRepository.Session;
import com.chiffrium.application.port.UserRepository;
import com.chiffrium.application.settings.SettingsService;
import com.chiffrium.domain.security.PasswordPolicy;
import com.chiffrium.domain.security.Role;
import com.chiffrium.domain.security.User;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Authentification locale : premier démarrage, connexion avec verrouillage progressif, sessions à
 * expiration (inactivité + durée maximale), changement de mot de passe. Toutes les étapes sont auditées.
 */
public final class AuthService {

    static final int MAX_FAILED_ATTEMPTS = 5;
    static final Duration LOCK_DURATION = Duration.ofMinutes(15);
    /** Écriture de la dernière activité au plus une fois par intervalle (limite les écritures en base). */
    static final Duration TOUCH_INTERVAL = Duration.ofMinutes(1);
    private static final int TOKEN_BYTES = 32;
    static final String ANONYMOUS = "anonyme";
    static final String GENERIC_FAILURE = "Identifiant ou mot de passe incorrect.";

    private final UserRepository users;
    private final SessionRepository sessions;
    private final PasswordHasher hasher;
    private final AuditService audit;
    private final SettingsService settings;
    private final SetupTokenStore setupTokens;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    /** Empreinte factice : vérifiée quand l'identifiant n'existe pas, pour un temps de réponse identique. */
    private final String dummyHash;

    public AuthService(UserRepository users, SessionRepository sessions, PasswordHasher hasher, AuditService audit,
                       SettingsService settings, SetupTokenStore setupTokens, Clock clock) {
        this.users = users;
        this.sessions = sessions;
        this.hasher = hasher;
        this.audit = audit;
        this.settings = settings;
        this.setupTokens = setupTokens;
        this.clock = clock;
        this.dummyHash = hasher.hash("dummy-password-for-timing".toCharArray());
    }

    /**
     * @param token     jeton à transmettre dans l'en-tête Authorization (affiché une seule fois)
     * @param user      compte connecté
     * @param expiresAt expiration absolue
     */
    public record LoginResult(String token, User user, Instant expiresAt) {
    }

    /**
     * @param actor auteur des actions de la requête
     * @param user  compte (pour le drapeau de changement de mot de passe)
     */
    public record AuthenticatedSession(Actor actor, User user) {
    }

    public boolean setupRequired() {
        return users.count() == 0;
    }

    /** Crée le premier administrateur (uniquement si aucun compte n'existe et avec le jeton d'installation). */
    public synchronized LoginResult setup(String setupToken, String username, char[] password, String displayName,
                                          String sourceIp) {
        if (!setupRequired()) {
            throw new AccessDeniedException("L'installation est déjà terminée.");
        }
        String expected = setupTokens.current().orElseThrow(() -> new AccessDeniedException("Jeton d'installation indisponible."));
        if (setupToken == null || !MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                setupToken.trim().getBytes(StandardCharsets.UTF_8))) {
            audit.record(anonymous(sourceIp), "SETUP_REJECTED", null, "jeton d'installation invalide");
            throw new AuthenticationException("Jeton d'installation invalide.");
        }
        String normalized = validateNewUsername(username);
        requireValidPassword(password, normalized);
        Instant now = clock.instant();
        User admin = new User(UUID.randomUUID().toString(), normalized, displayName == null ? normalized : displayName.trim(),
                null, Role.ADMIN, User.Source.LOCAL, hasher.hash(password), true, false, 0, null, now, null);
        users.save(admin);
        setupTokens.consume();
        audit.record(new Actor(admin.id(), admin.username(), Role.ADMIN, sourceIp), "SETUP_COMPLETED", admin.username(),
                "création du premier administrateur");
        return openSession(admin, sourceIp);
    }

    public LoginResult login(String username, char[] password, String sourceIp) {
        String normalized = User.normalizeUsername(username);
        Optional<User> found = normalized == null ? Optional.empty() : users.findByUsername(normalized);
        Instant now = clock.instant();
        if (found.isEmpty() || found.get().passwordHash() == null) {
            hasher.verify(password, dummyHash);
            audit.record(anonymous(sourceIp), "LOGIN_FAILURE", normalized, "compte inconnu ou sans mot de passe local");
            throw new AuthenticationException(GENERIC_FAILURE);
        }
        User user = found.get();
        if (user.isLocked(now)) {
            audit.record(asActor(user, sourceIp), "LOGIN_LOCKED", user.username(), "tentative pendant le verrouillage");
            throw new AuthenticationException("Compte temporairement verrouillé après plusieurs échecs. Réessayer plus tard.");
        }
        if (!hasher.verify(password, user.passwordHash())) {
            int attempts = user.failedAttempts() + 1;
            Instant lockUntil = attempts >= MAX_FAILED_ATTEMPTS ? now.plus(LOCK_DURATION) : null;
            users.save(user.withFailedAttempt(lockUntil != null ? 0 : attempts, lockUntil));
            audit.record(asActor(user, sourceIp), lockUntil != null ? "ACCOUNT_LOCKED" : "LOGIN_FAILURE",
                    user.username(), "échec no" + attempts);
            throw new AuthenticationException(GENERIC_FAILURE);
        }
        if (!user.enabled()) {
            audit.record(asActor(user, sourceIp), "LOGIN_FAILURE", user.username(), "compte désactivé");
            throw new AuthenticationException("Compte désactivé.");
        }
        User logged = user.withSuccessfulLogin(now);
        users.save(logged);
        audit.record(asActor(logged, sourceIp), "LOGIN_SUCCESS", logged.username(), null);
        return openSession(logged, sourceIp);
    }

    /** Ouvre une session pour un compte déjà authentifié (connexion SSO). */
    public LoginResult openSession(User user, String sourceIp) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(Duration.ofHours(settings.current().sessions().maxHours()));
        String token = newToken();
        sessions.create(new Session(hash(token), user.id(), now, now, expiresAt, sourceIp));
        return new LoginResult(token, user, expiresAt);
    }

    /**
     * @throws AuthenticationException si le jeton est absent, inconnu, expiré ou le compte désactivé
     */
    public AuthenticatedSession authenticate(String token, String sourceIp) {
        if (token == null || token.isBlank()) {
            throw new AuthenticationException("Authentification requise.");
        }
        String tokenHash = hash(token);
        Session session = sessions.findByTokenHash(tokenHash)
                .orElseThrow(() -> new AuthenticationException("Session inconnue ou expirée."));
        Instant now = clock.instant();
        Duration idle = Duration.ofMinutes(settings.current().sessions().idleMinutes());
        if (now.isAfter(session.expiresAt()) || now.isAfter(session.lastSeenAt().plus(idle))) {
            sessions.delete(tokenHash);
            throw new AuthenticationException("Session expirée, reconnectez-vous.");
        }
        User user = users.findById(session.userId())
                .filter(User::enabled)
                .orElseThrow(() -> {
                    sessions.delete(tokenHash);
                    return new AuthenticationException("Compte désactivé.");
                });
        if (now.isAfter(session.lastSeenAt().plus(TOUCH_INTERVAL))) {
            sessions.touch(tokenHash, now);
        }
        return new AuthenticatedSession(asActor(user, sourceIp), user);
    }

    public void logout(String token, Actor actor) {
        if (token != null) {
            sessions.delete(hash(token));
        }
        audit.record(actor, "LOGOUT", actor.username(), null);
    }

    /** Change le mot de passe de l'utilisateur courant ; toutes ses sessions sont fermées puis une nouvelle est ouverte. */
    public LoginResult changePassword(Actor actor, char[] currentPassword, char[] newPassword) {
        User user = users.findById(actor.userId()).orElseThrow(() -> new AuthenticationException("Compte introuvable."));
        if (user.passwordHash() == null || !hasher.verify(currentPassword, user.passwordHash())) {
            audit.record(actor, "PASSWORD_CHANGE_REJECTED", user.username(), "mot de passe actuel incorrect");
            throw new AuthenticationException("Mot de passe actuel incorrect.");
        }
        requireValidPassword(newPassword, user.username());
        if (hasher.verify(newPassword, user.passwordHash())) {
            throw new IllegalArgumentException("Le nouveau mot de passe doit être différent de l'ancien.");
        }
        User updated = user.withPassword(hasher.hash(newPassword), false);
        users.save(updated);
        sessions.deleteByUser(user.id());
        audit.record(actor, "PASSWORD_CHANGED", user.username(), null);
        return openSession(updated, actor.sourceIp());
    }

    public int purgeExpiredSessions() {
        return sessions.deleteExpired(clock.instant());
    }

    static void requireValidPassword(char[] password, String username) {
        List<String> violations = PasswordPolicy.violations(password == null ? null : new String(password), username);
        if (!violations.isEmpty()) {
            throw new IllegalArgumentException("Mot de passe refusé : " + String.join(" ", violations));
        }
    }

    static String validateNewUsername(String username) {
        String normalized = User.normalizeUsername(username);
        if (normalized == null || !normalized.matches("[a-z0-9][a-z0-9._@-]{2,63}")) {
            throw new IllegalArgumentException("Identifiant invalide : 3 à 64 caractères (lettres, chiffres, . _ @ -).");
        }
        return normalized;
    }

    private String newToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponible", e);
        }
    }

    private static Actor asActor(User user, String sourceIp) {
        return new Actor(user.id(), user.username(), user.role(), sourceIp);
    }

    /** Auteur des événements d'audit antérieurs à toute authentification. */
    static Actor anonymous(String sourceIp) {
        return new Actor(null, ANONYMOUS, Role.VIEWER, sourceIp);
    }
}
