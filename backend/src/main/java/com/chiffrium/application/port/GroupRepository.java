package com.chiffrium.application.port;

import com.chiffrium.domain.security.Group;
import com.chiffrium.domain.security.GroupInvitation;

import java.util.List;
import java.util.Optional;

/**
 * Persistance des groupes, de leurs membres et des propositions d'adhésion.
 */
public interface GroupRepository {

    /** Groupes avec leurs membres, par nom. */
    List<Group> findAll();

    Optional<Group> findById(String id);

    Optional<Group> findByName(String name);

    /** Crée ou met à jour l'en-tête du groupe (les membres sont gérés à part). */
    void save(Group group);

    void delete(String id);

    void setMember(String groupId, String userId, boolean manager);

    void removeMember(String groupId, String userId);

    /** Groupes d'un utilisateur. */
    List<Group.Membership> membershipsOf(String userId);

    void saveInvitation(GroupInvitation invitation);

    Optional<GroupInvitation> findInvitation(String id);

    /** Propositions en attente concernant un utilisateur (invitations reçues, demandes envoyées). */
    List<GroupInvitation> pendingForUser(String userId);

    /** Propositions en attente d'un groupe (invitations envoyées, demandes reçues). */
    List<GroupInvitation> pendingForGroup(String groupId);
}
