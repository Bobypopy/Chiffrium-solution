package com.chiffrium.domain.security;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonValue;

import java.time.Instant;
import java.util.Locale;

/**
 * Compte utilisateur. Le hachage du mot de passe n'est jamais sérialisé vers l'API.
 *
 * @param id                 identifiant technique (UUID)
 * @param username           identifiant de connexion (minuscules)
 * @param displayName        nom affiché
 * @param email              adresse (SSO)
 * @param role               rôle
 * @param source             origine du compte (local ou SSO)
 * @param passwordHash       hachage PBKDF2 (null pour un compte SSO)
 * @param enabled            compte actif
 * @param mustChangePassword changement de mot de passe exigé à la prochaine connexion
 * @param failedAttempts     échecs de connexion consécutifs
 * @param lockedUntil        verrouillage temporaire après trop d'échecs
 * @param createdAt          création
 * @param lastLoginAt        dernière connexion réussie
 */
public record User(
        String id,
        String username,
        String displayName,
        String email,
        Role role,
        Source source,
        @JsonIgnore String passwordHash,
        boolean enabled,
        boolean mustChangePassword,
        int failedAttempts,
        Instant lockedUntil,
        Instant createdAt,
        Instant lastLoginAt) {

    /** Origine d'un compte. */
    public enum Source {
        LOCAL, OIDC;

        @JsonValue
        public String id() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    public static String normalizeUsername(String username) {
        return username == null ? null : username.trim().toLowerCase(Locale.ROOT);
    }

    public boolean isLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    public User withRole(Role newRole) {
        return new User(id, username, displayName, email, newRole, source, passwordHash, enabled, mustChangePassword,
                failedAttempts, lockedUntil, createdAt, lastLoginAt);
    }

    public User withEnabled(boolean value) {
        return new User(id, username, displayName, email, role, source, passwordHash, value, mustChangePassword,
                0, null, createdAt, lastLoginAt);
    }

    public User withPassword(String newHash, boolean mustChange) {
        return new User(id, username, displayName, email, role, source, newHash, enabled, mustChange, 0, null,
                createdAt, lastLoginAt);
    }

    public User withFailedAttempt(int attempts, Instant lockUntil) {
        return new User(id, username, displayName, email, role, source, passwordHash, enabled, mustChangePassword,
                attempts, lockUntil, createdAt, lastLoginAt);
    }

    public User withSuccessfulLogin(Instant now) {
        return new User(id, username, displayName, email, role, source, passwordHash, enabled, mustChangePassword,
                0, null, createdAt, now);
    }

    public User withProfile(String newDisplayName, String newEmail) {
        return new User(id, username, newDisplayName, newEmail, role, source, passwordHash, enabled,
                mustChangePassword, failedAttempts, lockedUntil, createdAt, lastLoginAt);
    }
}
