package com.chiffrium.api;

import com.chiffrium.application.AnalysisService;
import com.chiffrium.application.CatalogRequestService;
import com.chiffrium.application.RetentionService;
import com.chiffrium.application.security.Actor;
import com.chiffrium.application.security.AuditArchiveService;
import com.chiffrium.application.security.AuditService;
import com.chiffrium.application.security.NotificationService;
import com.chiffrium.application.security.GroupService;
import com.chiffrium.application.security.UserService;
import com.chiffrium.application.security.UserService.UserWithPassword;
import com.chiffrium.application.settings.Settings;
import com.chiffrium.application.settings.SettingsService;
import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.model.AnalysisStatus;
import com.chiffrium.domain.security.AuditEvent;
import com.chiffrium.domain.security.CatalogRequest;
import com.chiffrium.domain.security.GroupInvitation;
import com.chiffrium.domain.security.Permission;
import com.chiffrium.domain.security.Role;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HttpStatus;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Administration : comptes, journal d'audit, paramètres et stockage.
 */
final class AdminRoutes {

    private static final String ID = "id";
    private static final int DEFAULT_AUDIT_PAGE = 100;
    private static final String AUDIT_EXPORT_FILE_NAME = "journal-audit.json";
    /** Fenêtre des indicateurs "récents" de la vue d'ensemble. */
    private static final Duration RECENT_WINDOW = Duration.ofHours(24);
    private static final int RECENT_EVENTS = 500;

    private final UserService users;
    private final AuditService audit;
    private final SettingsService settings;
    private final RetentionService retention;
    private final AnalysisService analyses;
    private final CatalogRequestService catalogRequests;
    private final GroupService groups;
    private final AuditArchiveService auditArchive;
    private final NotificationService notifications;

    AdminRoutes(UserService users, AuditService audit, AuditArchiveService auditArchive,
                SettingsService settings, RetentionService retention, AnalysisService analyses,
                CatalogRequestService catalogRequests, GroupService groups, NotificationService notifications) {
        this.users = users;
        this.audit = audit;
        this.auditArchive = auditArchive;
        this.notifications = notifications;
        this.settings = settings;
        this.retention = retention;
        this.analyses = analyses;
        this.catalogRequests = catalogRequests;
        this.groups = groups;
    }

    record CreateUserRequest(String username, String displayName, String email, Role role) {
    }

    record UpdateUserRequest(Role role, Boolean enabled, String displayName, String email) {
    }

    void register(Javalin server) {
        server.get("/api/admin/overview", this::overview);
        server.get("/api/admin/users", ctx -> ctx.json(users.list(RequestContext.actor(ctx))));
        server.post("/api/admin/users", this::createUser);
        server.patch("/api/admin/users/{id}", this::updateUser);
        server.post("/api/admin/users/{id}/reset-password", ctx ->
                ctx.json(users.resetPassword(RequestContext.actor(ctx), ctx.pathParam(ID))));

        server.get("/api/admin/audit", this::searchAudit);
        server.get("/api/admin/audit/verify", ctx -> {
            requireAudit(ctx);
            AuditService.Verification verification = audit.verify();
            AuditArchiveService.ExportState export = auditArchive.state();
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("intact", verification.intact());
            body.put("entries", verification.entries());
            body.put("firstBrokenSeq", verification.firstBrokenSeq());
            body.put("problem", verification.problem());
            body.put("anchoredUpTo", verification.anchoredUpTo());
            body.put("purgedUpTo", verification.purgedUpTo());
            // Un collecteur injoignable ne doit pas rester visible seulement dans les journaux du serveur.
            body.put("export", Map.of("targets", String.valueOf(export.targets()),
                    "lastAttemptAt", String.valueOf(export.attemptedAt()),
                    "lastSuccessAt", String.valueOf(export.succeededAt()),
                    "error", String.valueOf(export.error())));
            ctx.json(body);
        });
        server.get("/api/admin/audit/export", this::exportAudit);

        server.get("/api/admin/settings", ctx -> ctx.json(settings.view(RequestContext.actor(ctx))));
        server.put("/api/admin/settings", ctx ->
                ctx.json(settings.update(RequestContext.actor(ctx), ctx.bodyAsClass(Settings.class))));
        // Essai du relais SMTP : un réglage de messagerie se vérifie mal autrement qu'en envoyant un message.
        server.post("/api/admin/settings/email/test", ctx -> {
            Actor actor = RequestContext.actor(ctx);
            actor.require(Permission.MANAGE_SETTINGS);
            try {
                String address = notifications.sendTestEmail(actor);
                audit.record(actor, "EMAIL_TEST_SENT", address, "essai du relais SMTP");
                ctx.json(Map.of("sentTo", address));
            } catch (IllegalStateException e) {
                // Relais absent, injoignable ou refusant : l'administrateur doit lire la cause, pas "erreur
                // interne". L'échec est tracé, comme l'envoi réussi.
                audit.record(actor, "EMAIL_TEST_FAILED", null, e.getMessage());
                throw new ApiServer.Misconfigured("Essai de courriel : " + e.getMessage());
            }
        });

        server.get("/api/admin/storage", this::storage);
        server.post("/api/admin/storage/clean-workspaces", ctx -> {
            Actor actor = RequestContext.actor(ctx);
            actor.require(Permission.MANAGE_SETTINGS);
            RetentionService.Cleanup cleanup = retention.cleanWorkspaces();
            audit.record(actor, "WORKSPACES_CLEANED", null, cleanup.removed() + " dossier(s)");
            ctx.json(cleanup);
        });
        server.post("/api/admin/storage/purge", ctx -> {
            Actor actor = RequestContext.actor(ctx);
            actor.require(Permission.MANAGE_SETTINGS);
            audit.record(actor, "RETENTION_TRIGGERED", null, "purge manuelle");
            ctx.json(retention.apply());
        });
    }

    /** Vue d'ensemble : ce qui demande l'attention d'un administrateur. */
    private void overview(Context ctx) {
        Actor actor = RequestContext.actor(ctx);
        actor.require(Permission.MANAGE_SETTINGS);
        List<AnalysisJob> jobs = analyses.list(actor);
        Instant since = Instant.now().minus(RECENT_WINDOW);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("users", users.list(actor).size());
        body.put("groups", groups.directory(actor).size());
        body.put("analyses", jobs.size());
        body.put("analysesRunning", jobs.stream().filter(j -> j.status() == AnalysisStatus.RUNNING).count());
        body.put("analysesQueued", jobs.stream().filter(j -> j.status() == AnalysisStatus.QUEUED).count());
        body.put("analysesFailedRecently", jobs.stream().filter(j -> j.status() == AnalysisStatus.FAILED
                && j.finishedAt() != null && j.finishedAt().isAfter(since)).count());
        body.put("pendingCatalogRequests", catalogRequests.list(actor).stream()
                .filter(r -> r.status() == CatalogRequest.Status.PENDING).count());
        body.put("pendingJoinRequests", groups.directory(actor).stream().mapToLong(g -> g.pending().stream()
                .filter(i -> i.kind() == GroupInvitation.Kind.JOIN_REQUEST).count()).sum());
        body.put("failedLoginsRecently", audit.search(null, "LOGIN_FAILURE", RECENT_EVENTS, 0).stream()
                .filter(e -> e.timestamp().isAfter(since)).count());
        body.put("auditIntact", audit.verify().intact());
        body.put("usedBytes", retention.usedBytes());
        body.put("workspaceBytes", retention.workspaceBytes());
        ctx.json(body);
    }

    private void createUser(Context ctx) {
        CreateUserRequest request = ctx.bodyAsClass(CreateUserRequest.class);
        UserWithPassword created = users.create(RequestContext.actor(ctx), request.username(), request.displayName(),
                request.email(), request.role() == null ? Role.VIEWER : request.role());
        ctx.status(HttpStatus.CREATED).json(created);
    }

    private void updateUser(Context ctx) {
        UpdateUserRequest request = ctx.bodyAsClass(UpdateUserRequest.class);
        ctx.json(users.update(RequestContext.actor(ctx), ctx.pathParam(ID), request.role(), request.enabled(),
                request.displayName(), request.email()));
    }

    private void searchAudit(Context ctx) {
        requireAudit(ctx);
        int limit = ctx.queryParamAsClass("limit", Integer.class).getOrDefault(DEFAULT_AUDIT_PAGE);
        int offset = ctx.queryParamAsClass("offset", Integer.class).getOrDefault(0);
        ctx.json(audit.search(ctx.queryParam("actor"), ctx.queryParam("action"), limit, offset));
    }

    private void exportAudit(Context ctx) {
        Actor actor = requireAudit(ctx);
        audit.record(actor, "AUDIT_EXPORTED", null, null);
        List<AuditEvent> events = audit.all();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("verification", audit.verify());
        body.put("events", events);
        ctx.header("Content-Disposition", "attachment; filename=\"" + AUDIT_EXPORT_FILE_NAME + "\"");
        ctx.json(body);
    }

    private void storage(Context ctx) {
        RequestContext.actor(ctx).require(Permission.MANAGE_SETTINGS);
        Settings.Storage storage = settings.current().storage();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("usedBytes", retention.usedBytes());
        body.put("maxStorageMb", storage.maxStorageMb());
        body.put("retentionDays", storage.retentionDays());
        body.put("keepRawOutputs", storage.keepRawOutputs());
        body.put("workspaceBytes", retention.workspaceBytes());
        ctx.json(body);
    }

    private static Actor requireAudit(Context ctx) {
        Actor actor = RequestContext.actor(ctx);
        actor.require(Permission.VIEW_AUDIT);
        return actor;
    }
}
