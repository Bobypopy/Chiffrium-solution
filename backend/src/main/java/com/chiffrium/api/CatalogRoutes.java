package com.chiffrium.api;

import com.chiffrium.application.CatalogService;
import com.chiffrium.application.security.Actor;
import com.chiffrium.application.security.AuditService;
import com.chiffrium.domain.policy.AlgorithmCatalog;
import com.chiffrium.domain.policy.AlgorithmDefinition;
import com.chiffrium.domain.security.Permission;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HttpStatus;

/**
 * Catalogue d'algorithmes : consultation, édition d'une entrée, suppression, import / export complet
 * (pour partager la politique cryptographique entre installations).
 */
final class CatalogRoutes {

    private static final String ID = "id";
    private static final String EXPORT_FILE_NAME = "catalogue-algorithmes.json";

    private final CatalogService catalog;
    private final AuditService audit;

    CatalogRoutes(CatalogService catalog, AuditService audit) {
        this.catalog = catalog;
        this.audit = audit;
    }

    void register(Javalin server) {
        server.get("/api/catalog", ctx -> {
            RequestContext.actor(ctx).require(Permission.VIEW_REPORTS);
            ctx.json(catalog.catalog());
        });
        server.put("/api/catalog", this::replace);
        server.get("/api/catalog/export", this::export);
        // Publier : fige un numéro de version et une empreinte, pour que les autres installations sachent
        // exactement quelle politique elles appliquent.
        server.post("/api/catalog/publish", ctx -> ctx.json(catalog.publish(RequestContext.actor(ctx),
                ctx.bodyAsClass(PublishBody.class).name())));
        server.put("/api/catalog/algorithms/{id}", this::upsert);
        server.get("/api/catalog/reference-oids", ctx -> {
            RequestContext.actor(ctx).require(Permission.VIEW_REPORTS);
            ctx.json(catalog.referenceOids());
        });
        server.delete("/api/catalog/algorithms/{id}", ctx -> {
            catalog.remove(RequestContext.actor(ctx), ctx.pathParam(ID));
            ctx.status(HttpStatus.NO_CONTENT);
        });
    }

    private void upsert(Context ctx) {
        AlgorithmDefinition definition = ctx.bodyAsClass(AlgorithmDefinition.class);
        if (definition.id() == null || !definition.id().equals(ctx.pathParam(ID))) {
            throw new IllegalArgumentException("L'identifiant du corps doit correspondre à celui de l'URL.");
        }
        catalog.upsert(RequestContext.actor(ctx), definition);
        ctx.json(definition);
    }

    private void replace(Context ctx) {
        AlgorithmCatalog imported = ctx.bodyAsClass(AlgorithmCatalog.class);
        ctx.json(catalog.replace(RequestContext.actor(ctx), imported));
    }

    private void export(Context ctx) {
        Actor actor = RequestContext.actor(ctx);
        actor.require(Permission.VIEW_REPORTS);
        ctx.header("Content-Disposition", "attachment; filename=\"" + EXPORT_FILE_NAME + "\"");
        audit.record(actor, "CATALOG_EXPORTED", null, null);
        ctx.json(catalog.catalog());
    }

    /** Corps de la publication : le nom de la politique (optionnel). */
    record PublishBody(String name) {
    }
}
