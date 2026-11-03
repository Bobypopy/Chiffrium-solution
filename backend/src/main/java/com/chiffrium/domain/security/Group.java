package com.chiffrium.domain.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Groupe d'utilisateurs (équipe, projet). Les analyses rattachées à un groupe sont visibles de ses membres ;
 * ses responsables invitent, acceptent les demandes d'adhésion et gèrent les analyses du groupe.
 * Personne n'entre dans un groupe sans l'avoir accepté.
 *
 * @param name        nom unique
 * @param visibility  privé (sur invitation) ou public (visible dans l'annuaire, adhésion sur demande)
 * @param createdAt   date de création
 * @param members     membres (vide quand seul l'en-tête du groupe est chargé)
 */
public record Group(String id, String name, String description, Visibility visibility, Instant createdAt,
                    List<Member> members) {

    public static final int MAX_NAME_LENGTH = 100;
    public static final int MAX_DESCRIPTION_LENGTH = 500;

    public Group {
        visibility = visibility == null ? Visibility.PRIVATE : visibility;
        members = members == null ? List.of() : List.copyOf(members);
    }

    /** Visibilité dans l'annuaire des groupes. */
    public enum Visibility {
        PRIVATE, PUBLIC;

        @JsonValue
        public String id() {
            return name().toLowerCase(Locale.ROOT);
        }

        @JsonCreator
        public static Visibility fromId(String value) {
            return Arrays.stream(values()).filter(v -> v.name().equalsIgnoreCase(value)).findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Visibilité inconnue : " + value));
        }
    }

    /**
     * @param userId      compte
     * @param username    identifiant
     * @param displayName nom affiché
     * @param manager     responsable du groupe
     */
    public record Member(String userId, String username, String displayName, boolean manager) {
    }

    /**
     * Appartenance d'un utilisateur à un groupe.
     *
     * @param manager   l'utilisateur en est responsable
     */
    public record Membership(String groupId, String groupName, boolean manager) {
    }

    public boolean isManager(String userId) {
        return members.stream().anyMatch(m -> m.manager() && m.userId().equals(userId));
    }

    public boolean isMember(String userId) {
        return members.stream().anyMatch(m -> m.userId().equals(userId));
    }

    public long managerCount() {
        return members.stream().filter(Member::manager).count();
    }

    public Group withHeader(String newName, String newDescription, Visibility newVisibility) {
        return new Group(id, newName, newDescription, newVisibility, createdAt, members);
    }
}
