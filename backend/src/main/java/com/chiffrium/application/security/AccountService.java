package com.chiffrium.application.security;

import com.chiffrium.application.port.AnalysisRepository;
import com.chiffrium.application.port.CatalogRequestRepository;
import com.chiffrium.application.port.FavoriteRepository;
import com.chiffrium.application.port.GroupRepository;
import com.chiffrium.application.port.UserRepository;
import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.security.User;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Espace personnel : profil modifiable par l'utilisateur lui-même et export de ses données (droit d'accès,
 * article 15 du RGPD).
 */
public final class AccountService {

    static final int MAX_DISPLAY_NAME = 200;
    static final int MAX_EMAIL = 320;
    /** Entrées du journal d'audit incluses dans l'export personnel. */
    static final int EXPORTED_AUDIT_ENTRIES = 500;

    private final UserRepository users;
    private final GroupRepository groups;
    private final FavoriteRepository favorites;
    private final CatalogRequestRepository catalogRequests;
    private final AnalysisRepository analyses;
    private final NotificationService notifications;
    private final AuditService audit;
    private final Clock clock;

    public AccountService(UserRepository users, GroupRepository groups, FavoriteRepository favorites,
                          CatalogRequestRepository catalogRequests, AnalysisRepository analyses,
                          NotificationService notifications, AuditService audit, Clock clock) {
        this.users = users;
        this.groups = groups;
        this.favorites = favorites;
        this.catalogRequests = catalogRequests;
        this.analyses = analyses;
        this.notifications = notifications;
        this.audit = audit;
        this.clock = clock;
    }

    public User updateProfile(Actor actor, String displayName, String email) {
        User user = current(actor);
        String name = displayName == null || displayName.isBlank() ? user.displayName() : displayName.strip();
        String mail = email == null ? user.email() : email.isBlank() ? null : email.strip();
        if (name.length() > MAX_DISPLAY_NAME || mail != null && (mail.length() > MAX_EMAIL || !mail.contains("@"))) {
            throw new IllegalArgumentException("Nom ou adresse e-mail invalide.");
        }
        User updated = user.withProfile(name, mail);
        users.save(updated);
        audit.record(actor, "PROFILE_UPDATED", user.username(), null);
        return updated;
    }

    /** Toutes les données personnelles de l'utilisateur, dans un format lisible et réutilisable (JSON). */
    public Map<String, Object> exportPersonalData(Actor actor) {
        User user = current(actor);
        Map<String, Object> export = new LinkedHashMap<>();
        export.put("exportedAt", clock.instant());
        export.put("account", user);
        export.put("groups", groups.membershipsOf(user.id()));
        export.put("pendingInvitations", groups.pendingForUser(user.id()));
        export.put("favorites", favorites.analysisIds(user.id()));
        List<Map<String, Object>> mine = analyses.findAll().stream()
                .filter(job -> user.username().equals(job.requestedBy()))
                .map(AccountService::summary)
                .toList();
        export.put("analyses", mine);
        export.put("catalogRequests", catalogRequests.findAll().stream()
                .filter(r -> user.username().equals(r.requestedBy())).toList());
        export.put("notifications", notifications.list(actor, false));
        export.put("auditTrail", audit.search(user.username(), null, EXPORTED_AUDIT_ENTRIES, 0));
        audit.record(actor, "PERSONAL_DATA_EXPORTED", user.username(), null);
        return export;
    }

    private static Map<String, Object> summary(AnalysisJob job) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("id", job.id());
        summary.put("target", job.request().target());
        summary.put("label", job.label());
        summary.put("groupId", job.groupId());
        summary.put("status", job.status());
        summary.put("createdAt", job.createdAt());
        return summary;
    }

    private User current(Actor actor) {
        return users.findById(actor.userId()).orElseThrow(() -> new AuthenticationException("Compte introuvable."));
    }
}
