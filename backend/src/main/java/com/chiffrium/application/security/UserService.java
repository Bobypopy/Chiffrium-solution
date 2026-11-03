package com.chiffrium.application.security;

import com.chiffrium.application.port.PasswordHasher;
import com.chiffrium.application.port.SessionRepository;
import com.chiffrium.application.port.UserRepository;
import com.chiffrium.domain.security.Permission;
import com.chiffrium.domain.security.Role;
import com.chiffrium.domain.security.User;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Administration des comptes. Garde-fous : impossible de désactiver ou rétrograder le dernier
 * administrateur actif, ni de se désactiver soi-même ; les mots de passe temporaires sont générés
 * aléatoirement et doivent être changés à la première connexion.
 */
public final class UserService {

    static final int TEMPORARY_PASSWORD_LENGTH = 16;
    private static final String PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_!";

    private final UserRepository users;
    private final SessionRepository sessions;
    private final PasswordHasher hasher;
    private final AuditService audit;
    private final NotificationService notifier;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public UserService(UserRepository users, SessionRepository sessions, PasswordHasher hasher, AuditService audit,
                       NotificationService notifier, Clock clock) {
        this.notifier = notifier;
        this.users = users;
        this.sessions = sessions;
        this.hasher = hasher;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * @param user              compte créé ou modifié
     * @param temporaryPassword mot de passe à communiquer (une seule fois), null si inchangé
     */
    public record UserWithPassword(User user, String temporaryPassword) {
    }

    public List<User> list(Actor actor) {
        actor.require(Permission.MANAGE_USERS);
        return users.findAll().stream().sorted(Comparator.comparing(User::username)).toList();
    }

    public UserWithPassword create(Actor actor, String username, String displayName, String email, Role role) {
        actor.require(Permission.MANAGE_USERS);
        String normalized = AuthService.validateNewUsername(username);
        if (users.findByUsername(normalized).isPresent()) {
            throw new IllegalArgumentException("Cet identifiant existe déjà.");
        }
        String temporary = temporaryPassword();
        User user = new User(UUID.randomUUID().toString(), normalized,
                displayName == null || displayName.isBlank() ? normalized : displayName.trim(),
                blankToNull(email), Objects.requireNonNull(role, "role"), User.Source.LOCAL,
                hasher.hash(temporary.toCharArray()), true, true, 0, null, clock.instant(), null);
        users.save(user);
        audit.record(actor, "USER_CREATED", user.username(), "rôle " + role.id());
        return new UserWithPassword(user, temporary);
    }

    public User update(Actor actor, String userId, Role role, Boolean enabled, String displayName, String email) {
        actor.require(Permission.MANAGE_USERS);
        User user = users.findById(userId).orElseThrow(() -> new IllegalArgumentException("Compte introuvable."));
        User updated = user;
        if (role != null && role != user.role()) {
            if (user.role() == Role.ADMIN) {
                requireAnotherActiveAdmin(user);
            }
            updated = updated.withRole(role);
            audit.record(actor, "USER_ROLE_CHANGED", user.username(), user.role().id() + " -> " + role.id());
            notifier.notifyUser(user.id(), NotificationService.ACCOUNT, "Votre rôle a changé : " + role.id(),
                    "Modifié par " + actor.username() + ".", null);
        }
        if (enabled != null && enabled != user.enabled()) {
            if (!enabled) {
                if (user.id().equals(actor.userId())) {
                    throw new IllegalArgumentException("Impossible de désactiver son propre compte.");
                }
                if (user.role() == Role.ADMIN) {
                    requireAnotherActiveAdmin(user);
                }
                sessions.deleteByUser(user.id());
            }
            updated = updated.withEnabled(enabled);
            audit.record(actor, enabled ? "USER_ENABLED" : "USER_DISABLED", user.username(), null);
        }
        if (displayName != null || email != null) {
            updated = updated.withProfile(displayName == null ? updated.displayName() : displayName.trim(),
                    email == null ? updated.email() : blankToNull(email));
        }
        users.save(updated);
        return updated;
    }

    public UserWithPassword resetPassword(Actor actor, String userId) {
        actor.require(Permission.MANAGE_USERS);
        User user = users.findById(userId).orElseThrow(() -> new IllegalArgumentException("Compte introuvable."));
        if (user.source() != User.Source.LOCAL) {
            throw new IllegalArgumentException("Compte SSO : le mot de passe est géré par le fournisseur d'identité.");
        }
        String temporary = temporaryPassword();
        User updated = user.withPassword(hasher.hash(temporary.toCharArray()), true);
        users.save(updated);
        sessions.deleteByUser(user.id());
        audit.record(actor, "USER_PASSWORD_RESET", user.username(), null);
        return new UserWithPassword(updated, temporary);
    }

    private void requireAnotherActiveAdmin(User target) {
        long otherAdmins = users.findAll().stream()
                .filter(u -> u.role() == Role.ADMIN && u.enabled() && !u.id().equals(target.id()))
                .count();
        if (otherAdmins == 0) {
            throw new IllegalArgumentException("Au moins un administrateur actif doit subsister.");
        }
    }

    private String temporaryPassword() {
        StringBuilder password = new StringBuilder(TEMPORARY_PASSWORD_LENGTH);
        for (int i = 0; i < TEMPORARY_PASSWORD_LENGTH; i++) {
            password.append(PASSWORD_ALPHABET.charAt(random.nextInt(PASSWORD_ALPHABET.length())));
        }
        return password.toString();
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
