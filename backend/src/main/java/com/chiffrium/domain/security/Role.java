package com.chiffrium.domain.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;

/**
 * Rôles, du moins au plus privilégié. Principe du moindre privilège : un nouveau compte (y compris SSO)
 * reçoit {@link #VIEWER} sauf décision explicite d'un administrateur.
 */
public enum Role {
    /** Lecture des rapports de ses analyses et de ses groupes, propositions de modification du catalogue. */
    VIEWER(EnumSet.of(Permission.VIEW_REPORTS, Permission.REQUEST_CATALOG_CHANGE)),
    /** Lecture + lancement d'analyses et suppression des siennes. */
    ANALYST(EnumSet.of(Permission.VIEW_REPORTS, Permission.RUN_ANALYSIS, Permission.DELETE_OWN_ANALYSIS,
            Permission.REQUEST_CATALOG_CHANGE)),
    /** Toutes les permissions. */
    ADMIN(EnumSet.allOf(Permission.class));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = Set.copyOf(permissions);
    }

    public boolean can(Permission permission) {
        return permissions.contains(permission);
    }

    public Set<Permission> permissions() {
        return permissions;
    }

    @JsonValue
    public String id() {
        return name().toLowerCase(Locale.ROOT);
    }

    @JsonCreator
    public static Role fromId(String value) {
        return Arrays.stream(values())
                .filter(r -> r.name().equalsIgnoreCase(value))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Rôle inconnu : " + value));
    }
}
