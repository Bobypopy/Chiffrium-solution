package com.chiffrium.api;

import com.chiffrium.application.CatalogRequestService;
import com.chiffrium.application.security.AccountService;
import com.chiffrium.application.security.GroupService;
import com.chiffrium.application.security.NotificationService;
import com.chiffrium.domain.policy.AlgorithmDefinition;
import com.chiffrium.domain.security.CatalogRequest;
import com.chiffrium.domain.security.Group;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HttpStatus;

import java.util.List;
import java.util.Map;

/**
 * Travail en équipe et espace personnel : groupes (annuaire, création, invitations, demandes d'adhésion,
 * départ), notifications, profil et export des données personnelles, demandes de modification du catalogue.
 */
final class CollaborationRoutes {

    private static final String ID = "id";
    private static final String USER_ID = "userId";
    private static final String EXPORT_FILE_NAME = "mes-donnees-chiffrium.json";

    private final GroupService groups;
    private final CatalogRequestService requests;
    private final NotificationService notifications;
    private final AccountService account;

    CollaborationRoutes(GroupService groups, CatalogRequestService requests, NotificationService notifications,
                        AccountService account) {
        this.groups = groups;
        this.requests = requests;
        this.notifications = notifications;
        this.account = account;
    }

    record GroupRequest(String name, String description, Group.Visibility visibility) {
    }

    record InvitationRequest(String username, boolean manager, String message) {
    }

    record MessageRequest(String message) {
    }

    record ManagerRequest(boolean manager) {
    }

    record ProfileRequest(String displayName, String email) {
    }

    record ReadRequest(List<String> ids) {
    }

    record SubmitRequest(CatalogRequest.Kind kind, String algorithmId, AlgorithmDefinition proposal,
                         String justification, String groupId) {
    }

    record ReviewRequest(boolean approve, String comment) {
    }

    void register(Javalin server) {
        registerGroups(server);
        registerAccount(server);
        server.get("/api/catalog/requests", ctx -> ctx.json(requests.list(RequestContext.actor(ctx))));
        server.post("/api/catalog/requests", this::submit);
        server.post("/api/catalog/requests/{id}/withdraw", ctx ->
                ctx.json(requests.withdraw(RequestContext.actor(ctx), ctx.pathParam(ID))));
        server.post("/api/catalog/requests/{id}/review", ctx -> {
            ReviewRequest body = ctx.bodyAsClass(ReviewRequest.class);
            ctx.json(requests.review(RequestContext.actor(ctx), ctx.pathParam(ID), body.approve(), body.comment()));
        });
    }

    private void registerGroups(Javalin server) {
        server.get("/api/groups", ctx -> ctx.json(groups.directory(RequestContext.actor(ctx))));
        server.post("/api/groups", ctx -> {
            GroupRequest body = ctx.bodyAsClass(GroupRequest.class);
            ctx.status(HttpStatus.CREATED).json(groups.create(RequestContext.actor(ctx), body.name(),
                    body.description(), body.visibility()));
        });
        server.patch("/api/groups/{id}", ctx -> {
            GroupRequest body = ctx.bodyAsClass(GroupRequest.class);
            ctx.json(groups.update(RequestContext.actor(ctx), ctx.pathParam(ID), body.name(), body.description(),
                    body.visibility()));
        });
        server.delete("/api/groups/{id}", ctx -> {
            groups.delete(RequestContext.actor(ctx), ctx.pathParam(ID));
            ctx.status(HttpStatus.NO_CONTENT);
        });
        server.post("/api/groups/{id}/invitations", ctx -> {
            InvitationRequest body = ctx.bodyAsClass(InvitationRequest.class);
            ctx.status(HttpStatus.CREATED).json(groups.invite(RequestContext.actor(ctx), ctx.pathParam(ID),
                    body.username(), body.manager(), body.message()));
        });
        server.post("/api/groups/{id}/join", ctx -> {
            MessageRequest body = ctx.bodyAsClass(MessageRequest.class);
            ctx.status(HttpStatus.CREATED).json(groups.requestJoin(RequestContext.actor(ctx), ctx.pathParam(ID),
                    body.message()));
        });
        server.post("/api/groups/{id}/leave", ctx -> {
            groups.leave(RequestContext.actor(ctx), ctx.pathParam(ID));
            ctx.status(HttpStatus.NO_CONTENT);
        });
        server.delete("/api/groups/{id}/members/{userId}", ctx ->
                ctx.json(groups.removeMember(RequestContext.actor(ctx), ctx.pathParam(ID), ctx.pathParam(USER_ID))));
        server.put("/api/groups/{id}/members/{userId}/manager", ctx -> ctx.json(groups.setManager(
                RequestContext.actor(ctx), ctx.pathParam(ID), ctx.pathParam(USER_ID),
                ctx.bodyAsClass(ManagerRequest.class).manager())));
        server.post("/api/invitations/{id}/accept", ctx ->
                ctx.json(groups.accept(RequestContext.actor(ctx), ctx.pathParam(ID))));
        server.post("/api/invitations/{id}/decline", ctx ->
                ctx.json(groups.decline(RequestContext.actor(ctx), ctx.pathParam(ID))));
        server.post("/api/invitations/{id}/cancel", ctx ->
                ctx.json(groups.cancel(RequestContext.actor(ctx), ctx.pathParam(ID))));
        server.get("/api/me/groups", ctx -> ctx.json(groups.memberships(RequestContext.actor(ctx))));
        server.get("/api/me/invitations", ctx -> ctx.json(groups.myInvitations(RequestContext.actor(ctx))));
    }

    private void registerAccount(Javalin server) {
        server.patch("/api/me/profile", ctx -> {
            ProfileRequest body = ctx.bodyAsClass(ProfileRequest.class);
            ctx.json(account.updateProfile(RequestContext.actor(ctx), body.displayName(), body.email()));
        });
        server.get("/api/me/export", ctx -> {
            ctx.header("Content-Disposition", "attachment; filename=\"" + EXPORT_FILE_NAME + "\"");
            ctx.json(account.exportPersonalData(RequestContext.actor(ctx)));
        });
        server.get("/api/notifications", ctx -> ctx.json(notifications.list(RequestContext.actor(ctx),
                Boolean.parseBoolean(ctx.queryParam("unread")))));
        server.get("/api/notifications/count", ctx -> ctx.json(Map.of("unread",
                notifications.unreadCount(RequestContext.actor(ctx)))));
        server.post("/api/notifications/read", ctx -> {
            ReadRequest body = ctx.bodyAsClass(ReadRequest.class);
            notifications.markRead(RequestContext.actor(ctx), body.ids());
            ctx.status(HttpStatus.NO_CONTENT);
        });
    }

    private void submit(Context ctx) {
        SubmitRequest body = ctx.bodyAsClass(SubmitRequest.class);
        ctx.status(HttpStatus.CREATED).json(requests.submit(RequestContext.actor(ctx), body.kind(), body.algorithmId(),
                body.proposal(), body.justification(), body.groupId()));
    }
}
