package com.chiffrium.application;

import com.chiffrium.application.port.GroupRepository;
import com.chiffrium.application.security.Actor;
import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.security.Group;
import com.chiffrium.domain.security.Permission;

import java.util.List;
import java.util.Objects;

/**
 * Qui voit et qui gère une analyse :
 * <ul>
 *   <li>administrateur : toutes ;</li>
 *   <li>demandeur : les siennes ;</li>
 *   <li>membre d'un groupe : celles rattachées au groupe ;</li>
 *   <li>responsable d'un groupe : peut aussi supprimer celles du groupe.</li>
 * </ul>
 * Une analyse sans groupe est privée (demandeur et administrateurs).
 */
public final class AnalysisAccess {

    private final GroupRepository groups;

    public AnalysisAccess(GroupRepository groups) {
        this.groups = groups;
    }

    /** Vue figée des appartenances d'un acteur, à réutiliser pour filtrer une liste. */
    public final class Scope {
        private final Actor actor;
        private final List<Group.Membership> memberships;

        private Scope(Actor actor) {
            this.actor = actor;
            this.memberships = actor.userId() == null ? List.of() : groups.membershipsOf(actor.userId());
        }

        public boolean canView(AnalysisJob job) {
            if (!actor.can(Permission.VIEW_REPORTS)) {
                return false;
            }
            return actor.can(Permission.VIEW_ALL_ANALYSES) || isOwner(job)
                    || memberships.stream().anyMatch(m -> m.groupId().equals(job.groupId()));
        }

        public boolean canDelete(AnalysisJob job) {
            return actor.can(Permission.DELETE_ANY_ANALYSIS)
                    || isOwner(job) && actor.can(Permission.DELETE_OWN_ANALYSIS)
                    || memberships.stream().anyMatch(m -> m.manager() && m.groupId().equals(job.groupId()));
        }

        /** Rattacher une analyse à ce groupe : membre du groupe ou administrateur. */
        public boolean canUseGroup(String groupId) {
            return groupId == null || actor.can(Permission.VIEW_ALL_ANALYSES)
                    || memberships.stream().anyMatch(m -> m.groupId().equals(groupId));
        }

        public List<Group.Membership> memberships() {
            return memberships;
        }

        private boolean isOwner(AnalysisJob job) {
            return Objects.equals(actor.username(), job.requestedBy());
        }
    }

    public Scope scope(Actor actor) {
        return new Scope(actor);
    }
}
