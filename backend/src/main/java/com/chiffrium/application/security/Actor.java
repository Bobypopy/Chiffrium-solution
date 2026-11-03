package com.chiffrium.application.security;

import com.chiffrium.domain.security.AuditEvent;
import com.chiffrium.domain.security.Permission;
import com.chiffrium.domain.security.Role;

/**
 * Auteur d'une action (utilisateur authentifié ou système), transmis aux cas d'usage pour les
 * contrôles d'autorisation et la traçabilité.
 *
 * @param userId   identifiant du compte (null pour le système)
 * @param username identifiant de connexion
 * @param sourceIp adresse d'origine de la requête
 */
public record Actor(String userId, String username, Role role, String sourceIp) {

    public static final Actor SYSTEM = new Actor(null, AuditEvent.SYSTEM_ACTOR, Role.ADMIN, null);

    public boolean can(Permission permission) {
        return role.can(permission);
    }

    /**
     * @throws AccessDeniedException si la permission manque
     */
    public void require(Permission permission) {
        if (!can(permission)) {
            throw new AccessDeniedException("Action non autorisée pour le rôle " + role.id() + ".");
        }
    }
}
