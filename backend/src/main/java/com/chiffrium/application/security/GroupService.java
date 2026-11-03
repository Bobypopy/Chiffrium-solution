package com.chiffrium.application.security;

import com.chiffrium.application.port.GroupRepository;
import com.chiffrium.application.port.UserRepository;
import com.chiffrium.application.settings.Settings;
import com.chiffrium.domain.security.Group;
import com.chiffrium.domain.security.GroupInvitation;
import com.chiffrium.domain.security.GroupInvitation.Kind;
import com.chiffrium.domain.security.GroupInvitation.Status;
import com.chiffrium.domain.security.Permission;
import com.chiffrium.domain.security.User;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Groupes et adhésion consentie :
 * <ul>
 *   <li>un responsable (ou un administrateur) <b>invite</b> ; seul l'invité peut accepter ou refuser ;</li>
 *   <li>un utilisateur <b>demande</b> à rejoindre un groupe public ; un responsable accepte ou refuse ;</li>
 *   <li>chacun peut <b>quitter</b> un groupe ; le dernier responsable doit d'abord passer la main ;</li>
 *   <li>un responsable retire des membres, nomme d'autres responsables, modifie ou supprime le groupe.</li>
 * </ul>
 * Chaque étape est tracée dans l'audit et notifiée aux personnes concernées.
 */
public final class GroupService {

    private static final String MY_SPACE = "#/me";

    private final GroupRepository groups;
    private final UserRepository users;
    private final AuditService audit;
    private final NotificationService notifier;
    private final Supplier<Settings.Collaboration> collaboration;
    private final Clock clock;

    public GroupService(GroupRepository groups, UserRepository users, AuditService audit, NotificationService notifier,
                        Supplier<Settings.Collaboration> collaboration, Clock clock) {
        this.groups = groups;
        this.users = users;
        this.audit = audit;
        this.notifier = notifier;
        this.collaboration = collaboration;
        this.clock = clock;
    }

    /**
     * Vue d'un groupe pour un utilisateur donné.
     *
     * @param myRole       "manager", "member" ou null (non-membre)
     * @param members      membres (visibles des membres et des administrateurs)
     * @param memberCount  nombre de membres
     * @param pending      propositions en attente (visibles des responsables et des administrateurs)
     * @param joinRequested l'utilisateur a une demande d'adhésion en attente
     */
    public record GroupView(String id, String name, String description, Group.Visibility visibility, String myRole,
                            int memberCount, List<Group.Member> members, List<GroupInvitation> pending,
                            boolean joinRequested) {
    }

    /** Propositions en attente concernant l'utilisateur courant. */
    public record MyInvitations(List<GroupInvitation> received, List<GroupInvitation> sent) {
    }

    /** Annuaire : mes groupes, les groupes publics, et tous les groupes pour un administrateur. */
    public List<GroupView> directory(Actor actor) {
        boolean admin = actor.can(Permission.MANAGE_GROUPS);
        List<GroupInvitation> myPending = actor.userId() == null ? List.of() : groups.pendingForUser(actor.userId());
        List<GroupView> views = new ArrayList<>();
        for (Group group : groups.findAll()) {
            boolean member = group.isMember(actor.userId());
            if (!admin && !member && group.visibility() != Group.Visibility.PUBLIC) {
                continue;
            }
            boolean manager = group.isManager(actor.userId());
            String role = manager ? "manager" : member ? "member" : null;
            boolean canSeeMembers = admin || member;
            views.add(new GroupView(group.id(), group.name(), group.description(), group.visibility(), role,
                    group.members().size(), canSeeMembers ? group.members() : List.of(),
                    admin || manager ? groups.pendingForGroup(group.id()) : List.of(),
                    myPending.stream().anyMatch(i -> i.kind() == Kind.JOIN_REQUEST && i.groupId().equals(group.id()))));
        }
        return views;
    }

    /** Groupes de l'utilisateur courant (choix du groupe d'une analyse, filtres). */
    public List<Group.Membership> memberships(Actor actor) {
        return actor.userId() == null ? List.of() : groups.membershipsOf(actor.userId());
    }

    public MyInvitations myInvitations(Actor actor) {
        List<GroupInvitation> pending = actor.userId() == null ? List.of() : groups.pendingForUser(actor.userId());
        return new MyInvitations(pending.stream().filter(i -> i.kind() == Kind.INVITATION).toList(),
                pending.stream().filter(i -> i.kind() == Kind.JOIN_REQUEST).toList());
    }

    /** Création : réservée aux administrateurs, ou ouverte à tous selon les paramètres. Le créateur est responsable. */
    public Group create(Actor actor, String name, String description, Group.Visibility visibility) {
        if (!actor.can(Permission.MANAGE_GROUPS) && !collaboration.get().usersCanCreateGroups()) {
            throw new AccessDeniedException("La création de groupes est réservée aux administrateurs.");
        }
        String cleanName = validName(name);
        if (groups.findByName(cleanName).isPresent()) {
            throw new IllegalArgumentException("Un groupe porte déjà ce nom.");
        }
        Group group = new Group(UUID.randomUUID().toString(), cleanName, cleanText(description,
                Group.MAX_DESCRIPTION_LENGTH), visibility, clock.instant(), List.of());
        groups.save(group);
        if (actor.userId() != null) {
            groups.setMember(group.id(), actor.userId(), true);
        }
        audit.record(actor, "GROUP_CREATED", cleanName, group.visibility().id());
        return require(group.id());
    }

    public Group update(Actor actor, String groupId, String name, String description, Group.Visibility visibility) {
        Group existing = requireManager(actor, groupId);
        String cleanName = name == null ? existing.name() : validName(name);
        groups.findByName(cleanName).filter(g -> !g.id().equals(groupId)).ifPresent(g -> {
            throw new IllegalArgumentException("Un groupe porte déjà ce nom.");
        });
        groups.save(existing.withHeader(cleanName, description == null ? existing.description()
                : cleanText(description, Group.MAX_DESCRIPTION_LENGTH), visibility == null ? existing.visibility()
                : visibility));
        audit.record(actor, "GROUP_UPDATED", cleanName, null);
        return require(groupId);
    }

    /** Les analyses du groupe deviennent privées (visibles de leur demandeur et des administrateurs). */
    public void delete(Actor actor, String groupId) {
        Group group = requireManager(actor, groupId);
        groups.delete(groupId);
        audit.record(actor, "GROUP_DELETED", group.name(), group.members().size() + " membre(s)");
        notifier.notifyUsers(others(group, actor), NotificationService.GROUP_MEMBERSHIP,
                "Groupe \"" + group.name() + "\" supprimé", "Supprimé par " + actor.username()
                        + ". Ses analyses sont désormais privées.", null);
    }

    /** Invite un utilisateur ; s'il avait demandé à rejoindre le groupe, sa demande est acceptée. */
    public GroupInvitation invite(Actor actor, String groupId, String username, boolean manager, String message) {
        Group group = requireManager(actor, groupId);
        User user = users.findByUsername(username).filter(User::enabled)
                .orElseThrow(() -> new IllegalArgumentException("Utilisateur inconnu ou désactivé : " + username));
        if (group.isMember(user.id())) {
            throw new IllegalArgumentException(user.username() + " est déjà membre du groupe.");
        }
        Optional<GroupInvitation> existing = pending(groupId, user.id());
        if (existing.isPresent() && existing.get().kind() == Kind.JOIN_REQUEST) {
            return accept(actor, existing.get().id());
        }
        if (existing.isPresent()) {
            throw new IllegalArgumentException("Une invitation est déjà en attente pour " + user.username() + ".");
        }
        GroupInvitation invitation = new GroupInvitation(UUID.randomUUID().toString(), groupId, group.name(), user.id(),
                user.username(), Kind.INVITATION, manager, cleanText(message, GroupInvitation.MAX_MESSAGE_LENGTH),
                actor.username(), Status.PENDING, null, clock.instant(), null);
        groups.saveInvitation(invitation);
        audit.record(actor, "GROUP_INVITATION_SENT", group.name(), user.username() + (manager ? " (responsable)" : ""));
        notifier.notifyUser(user.id(), NotificationService.GROUP_INVITATION,
                actor.username() + " vous invite dans \"" + group.name() + "\"",
                invitation.message() != null ? invitation.message() : "Acceptez ou refusez l'invitation dans votre espace.",
                MY_SPACE);
        return invitation;
    }

    /** Demande d'adhésion à un groupe public. */
    public GroupInvitation requestJoin(Actor actor, String groupId, String message) {
        Group group = require(groupId);
        if (group.visibility() != Group.Visibility.PUBLIC) {
            throw new AccessDeniedException("Ce groupe est privé : il faut y être invité.");
        }
        if (group.isMember(actor.userId())) {
            throw new IllegalArgumentException("Vous êtes déjà membre de ce groupe.");
        }
        Optional<GroupInvitation> existing = pending(groupId, actor.userId());
        if (existing.isPresent() && existing.get().kind() == Kind.INVITATION) {
            return accept(actor, existing.get().id());
        }
        if (existing.isPresent()) {
            throw new IllegalArgumentException("Votre demande est déjà en attente.");
        }
        GroupInvitation request = new GroupInvitation(UUID.randomUUID().toString(), groupId, group.name(),
                actor.userId(), actor.username(), Kind.JOIN_REQUEST, false,
                cleanText(message, GroupInvitation.MAX_MESSAGE_LENGTH), actor.username(), Status.PENDING, null,
                clock.instant(), null);
        groups.saveInvitation(request);
        audit.record(actor, "GROUP_JOIN_REQUESTED", group.name(), null);
        notifyManagers(group, NotificationService.GROUP_JOIN_REQUEST,
                actor.username() + " demande à rejoindre \"" + group.name() + "\"",
                request.message() != null ? request.message() : "À accepter ou refuser dans la page Groupes.");
        return request;
    }

    /**
     * Accepte une proposition : l'invité pour une invitation, un responsable pour une demande d'adhésion.
     */
    public GroupInvitation accept(Actor actor, String invitationId) {
        GroupInvitation invitation = requirePending(invitationId);
        Group group = require(invitation.groupId());
        checkResponder(actor, invitation, group);
        groups.setMember(group.id(), invitation.userId(), invitation.kind() == Kind.INVITATION && invitation.manager());
        GroupInvitation accepted = invitation.answered(Status.ACCEPTED, actor.username(), clock.instant());
        groups.saveInvitation(accepted);
        audit.record(actor, "GROUP_MEMBER_JOINED", group.name(), invitation.username());
        if (invitation.kind() == Kind.INVITATION) {
            users.findByUsername(invitation.createdBy()).ifPresent(inviter -> notifier.notifyUser(inviter.id(),
                    NotificationService.GROUP_MEMBERSHIP, invitation.username() + " a rejoint \"" + group.name() + "\"",
                    null, "#/groups"));
        } else {
            notifier.notifyUser(invitation.userId(), NotificationService.GROUP_MEMBERSHIP,
                    "Bienvenue dans \"" + group.name() + "\"", "Demande acceptée par " + actor.username() + ".",
                    "#/groups");
        }
        return accepted;
    }

    public GroupInvitation decline(Actor actor, String invitationId) {
        GroupInvitation invitation = requirePending(invitationId);
        Group group = require(invitation.groupId());
        checkResponder(actor, invitation, group);
        GroupInvitation declined = invitation.answered(Status.DECLINED, actor.username(), clock.instant());
        groups.saveInvitation(declined);
        audit.record(actor, "GROUP_INVITATION_DECLINED", group.name(), invitation.username());
        if (invitation.kind() == Kind.INVITATION) {
            users.findByUsername(invitation.createdBy()).ifPresent(inviter -> notifier.notifyUser(inviter.id(),
                    NotificationService.GROUP_MEMBERSHIP, invitation.username() + " a décliné l'invitation dans \""
                            + group.name() + "\"", null, "#/groups"));
        } else {
            notifier.notifyUser(invitation.userId(), NotificationService.GROUP_MEMBERSHIP,
                    "Demande refusée pour \"" + group.name() + "\"", null, "#/groups");
        }
        return declined;
    }

    /** Annulation par son auteur (ou un responsable pour une invitation, ou un administrateur). */
    public GroupInvitation cancel(Actor actor, String invitationId) {
        GroupInvitation invitation = requirePending(invitationId);
        Group group = require(invitation.groupId());
        boolean author = invitation.createdBy().equals(actor.username());
        boolean managerOfInvitation = invitation.kind() == Kind.INVITATION && canManage(actor, group);
        if (!author && !managerOfInvitation && !actor.can(Permission.MANAGE_GROUPS)) {
            throw new AccessDeniedException("Seul l'auteur peut annuler cette proposition.");
        }
        GroupInvitation cancelled = invitation.answered(Status.CANCELLED, actor.username(), clock.instant());
        groups.saveInvitation(cancelled);
        audit.record(actor, "GROUP_INVITATION_CANCELLED", group.name(), invitation.username());
        return cancelled;
    }

    /** Quitter un groupe ; le dernier responsable doit d'abord nommer un successeur. */
    public void leave(Actor actor, String groupId) {
        Group group = require(groupId);
        if (!group.isMember(actor.userId())) {
            throw new IllegalArgumentException("Vous n'êtes pas membre de ce groupe.");
        }
        if (group.members().size() == 1) {
            // Sinon le groupe resterait sans personne : invisible à gérer, mais toujours listé et porteur
            // d'analyses partagées.
            throw new IllegalArgumentException("Vous êtes le seul membre de ce groupe : supprimez-le plutôt que "
                    + "de le quitter, ou invitez quelqu'un avant de partir.");
        }
        if (group.isManager(actor.userId()) && group.managerCount() == 1) {
            throw new IllegalArgumentException("Vous êtes le dernier responsable : nommez un autre responsable avant "
                    + "de quitter le groupe.");
        }
        groups.removeMember(groupId, actor.userId());
        audit.record(actor, "GROUP_MEMBER_LEFT", group.name(), actor.username());
        notifyManagers(group, NotificationService.GROUP_MEMBERSHIP, actor.username() + " a quitté \"" + group.name()
                + "\"", null);
    }

    public Group removeMember(Actor actor, String groupId, String userId) {
        Group group = requireManager(actor, groupId);
        if (userId.equals(actor.userId())) {
            throw new IllegalArgumentException("Pour vous retirer vous-même, quittez le groupe.");
        }
        Group.Member member = member(group, userId);
        groups.removeMember(groupId, userId);
        audit.record(actor, "GROUP_MEMBER_REMOVED", group.name(), member.username());
        notifier.notifyUser(userId, NotificationService.GROUP_MEMBERSHIP, "Vous avez été retiré de \"" + group.name()
                + "\"", "Par " + actor.username() + ".", null);
        return require(groupId);
    }

    /** Nomme ou retire un responsable (il doit toujours en rester au moins un tant que le groupe a des membres). */
    public Group setManager(Actor actor, String groupId, String userId, boolean manager) {
        Group group = requireManager(actor, groupId);
        Group.Member member = member(group, userId);
        if (!manager && member.manager() && group.managerCount() == 1) {
            throw new IllegalArgumentException("Le groupe doit garder au moins un responsable.");
        }
        groups.setMember(groupId, userId, manager);
        audit.record(actor, manager ? "GROUP_MANAGER_ADDED" : "GROUP_MANAGER_REMOVED", group.name(), member.username());
        if (manager) {
            notifier.notifyUser(userId, NotificationService.GROUP_MEMBERSHIP, "Vous êtes responsable de \""
                    + group.name() + "\"", "Nommé par " + actor.username() + ".", "#/groups");
        }
        return require(groupId);
    }

    private void checkResponder(Actor actor, GroupInvitation invitation, Group group) {
        boolean allowed = invitation.kind() == Kind.INVITATION
                ? invitation.userId().equals(actor.userId())
                : canManage(actor, group);
        if (!allowed) {
            throw new AccessDeniedException(invitation.kind() == Kind.INVITATION
                    ? "Seule la personne invitée peut répondre." : "Seul un responsable du groupe peut répondre.");
        }
    }

    private void notifyManagers(Group group, String kind, String title, String body) {
        List<String> managers = group.members().stream().filter(Group.Member::manager).map(Group.Member::userId).toList();
        if (managers.isEmpty()) {
            notifier.notifyPermission(Permission.MANAGE_GROUPS, kind, title, body, "#/groups");
        } else {
            notifier.notifyUsers(managers, kind, title, body, "#/groups");
        }
    }

    private static List<String> others(Group group, Actor actor) {
        return group.members().stream().map(Group.Member::userId).filter(id -> !id.equals(actor.userId())).toList();
    }

    private Optional<GroupInvitation> pending(String groupId, String userId) {
        return groups.pendingForGroup(groupId).stream().filter(i -> i.userId().equals(userId)).findFirst();
    }

    private boolean canManage(Actor actor, Group group) {
        return actor.can(Permission.MANAGE_GROUPS) || group.isManager(actor.userId());
    }

    private Group requireManager(Actor actor, String groupId) {
        Group group = require(groupId);
        if (!canManage(actor, group)) {
            throw new AccessDeniedException("Action réservée aux responsables du groupe.");
        }
        return group;
    }

    private Group require(String groupId) {
        return groups.findById(groupId).orElseThrow(() -> new IllegalArgumentException("Groupe introuvable."));
    }

    private GroupInvitation requirePending(String invitationId) {
        GroupInvitation invitation = groups.findInvitation(invitationId)
                .orElseThrow(() -> new IllegalArgumentException("Proposition introuvable."));
        if (invitation.status() != Status.PENDING) {
            throw new IllegalArgumentException("Cette proposition a déjà été traitée.");
        }
        return invitation;
    }

    private static Group.Member member(Group group, String userId) {
        return group.members().stream().filter(m -> m.userId().equals(userId)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Ce compte n'est pas membre du groupe."));
    }

    private static String validName(String name) {
        String clean = name == null ? "" : name.strip();
        if (clean.isEmpty() || clean.length() > Group.MAX_NAME_LENGTH) {
            throw new IllegalArgumentException("Nom de groupe obligatoire (" + Group.MAX_NAME_LENGTH + " caractères max).");
        }
        return clean;
    }

    private static String cleanText(String value, int max) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String clean = value.strip();
        if (clean.length() > max) {
            throw new IllegalArgumentException("Texte trop long (" + max + " caractères max).");
        }
        return clean;
    }
}
