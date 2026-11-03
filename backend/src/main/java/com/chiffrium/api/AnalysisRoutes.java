package com.chiffrium.api;

import com.chiffrium.application.AnalysisService;
import com.chiffrium.application.port.AnalysisRepository;
import com.chiffrium.application.port.AnalysisRepository.Artifact;
import com.chiffrium.application.security.Actor;
import com.chiffrium.application.security.AuditService;
import com.chiffrium.domain.model.AnalysisIds;
import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.security.Permission;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HttpStatus;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Analyses : soumission, suivi, suppression, favoris, comparaison et téléchargement des artefacts (déchiffrés à
 * la volée). Chaque accès passe par les règles de visibilité du service (groupes, demandeur, administrateur).
 */
final class AnalysisRoutes {

    private static final String ID = "id";
    private static final String OTHER = "other";
    private static final Pattern UNSAFE_FILE_CHARS = Pattern.compile("[^A-Za-z0-9._-]+");
    private static final int MAX_STEM_LENGTH = 60;
    /** Contenu et noms de l'archive complète, dans l'ordre d'importance. */
    private static final Map<Artifact, String> BUNDLE_NAMES = new LinkedHashMap<>();

    static {
        BUNDLE_NAMES.put(Artifact.CBOM, "cbom-%s.json");
        BUNDLE_NAMES.put(Artifact.REPORT, "rapport-%s.json");
        BUNDLE_NAMES.put(Artifact.SARIF, "chiffrium-%s.sarif");
        BUNDLE_NAMES.put(Artifact.LOG, "journal-%s.log");
    }

    private final AnalysisService analyses;
    private final AnalysisRepository repository;
    private final AuditService audit;
    private final Map<String, Object> info;

    AnalysisRoutes(AnalysisService analyses, AnalysisRepository repository, AuditService audit,
                   Map<String, Object> info) {
        this.analyses = analyses;
        this.repository = repository;
        this.audit = audit;
        this.info = Map.copyOf(info);
    }

    record GroupBody(String groupId) {
    }

    record LabelBody(String label) {
    }

    void register(Javalin server) {
        server.get("/api/info", ctx -> {
            RequestContext.actor(ctx).require(Permission.VIEW_REPORTS);
            ctx.json(info);
        });
        server.get("/api/analyses", ctx -> ctx.json(analyses.list(RequestContext.actor(ctx))));
        server.post("/api/analyses", this::submit);
        server.get("/api/analyses/{id}", ctx -> ctx.json(job(ctx)));
        server.delete("/api/analyses/{id}", this::delete);
        server.get("/api/analyses/{id}/report", ctx -> sendArtifact(ctx, Artifact.REPORT, download(ctx, "rapport-%s.json")));
        server.get("/api/analyses/{id}/cbom", ctx -> sendArtifact(ctx, Artifact.CBOM, "cbom-%s.json"));
        server.get("/api/analyses/{id}/sarif", ctx -> sendArtifact(ctx, Artifact.SARIF, "chiffrium-%s.sarif"));
        server.get("/api/analyses/{id}/log", ctx -> sendArtifact(ctx, Artifact.LOG, download(ctx, "journal-%s.log")));
        server.get("/api/analyses/{id}/bundle", this::sendBundle);
        server.get("/api/analyses/{id}/compare/{other}", ctx -> ctx.json(analyses.compare(RequestContext.actor(ctx),
                validId(ctx, ID), validId(ctx, OTHER))));
        server.get("/api/favorites", ctx -> ctx.json(analyses.favoriteIds(RequestContext.actor(ctx))));
        server.put("/api/analyses/{id}/favorite", ctx -> favorite(ctx, true));
        server.post("/api/analyses/{id}/cancel", ctx -> ctx.json(analyses.cancel(RequestContext.actor(ctx),
                validId(ctx, ID))));
        server.post("/api/analyses/{id}/rerun", ctx -> ctx.status(HttpStatus.ACCEPTED)
                .json(analyses.rerun(RequestContext.actor(ctx), validId(ctx, ID))));
        server.put("/api/analyses/{id}/group", ctx -> ctx.json(analyses.share(RequestContext.actor(ctx),
                validId(ctx, ID), ctx.bodyAsClass(GroupBody.class).groupId())));
        server.put("/api/analyses/{id}/label", ctx -> ctx.json(analyses.label(RequestContext.actor(ctx),
                validId(ctx, ID), ctx.bodyAsClass(LabelBody.class).label())));
        server.delete("/api/analyses/{id}/favorite", ctx -> favorite(ctx, false));
    }

    private void submit(Context ctx) {
        AnalysisSubmission submission = ctx.bodyAsClass(AnalysisSubmission.class);
        List<AnalysisJob> jobs = analyses.submit(RequestContext.actor(ctx), submission.toRequests(),
                submission.groupId());
        ctx.status(HttpStatus.ACCEPTED).json(jobs);
    }

    private void delete(Context ctx) {
        String id = validId(ctx, ID);
        if (!analyses.delete(RequestContext.actor(ctx), id)) {
            throw new ApiServer.NotFound("Analyse introuvable : " + id);
        }
        ctx.status(HttpStatus.NO_CONTENT);
    }

    private void favorite(Context ctx, boolean value) {
        analyses.setFavorite(RequestContext.actor(ctx), validId(ctx, ID), value);
        ctx.status(HttpStatus.NO_CONTENT);
    }

    private AnalysisJob job(Context ctx) {
        String id = validId(ctx, ID);
        return analyses.find(RequestContext.actor(ctx), id)
                .orElseThrow(() -> new ApiServer.NotFound("Analyse introuvable : " + id));
    }

    /** Le même contenu sert à l'affichage (sans paramètre) et au téléchargement ({@code ?download=true}). */
    private static String download(Context ctx, String downloadName) {
        return Boolean.parseBoolean(ctx.queryParam("download")) ? downloadName : null;
    }

    /**
     * @param downloadName modèle du nom de fichier téléchargé (null : affichage dans l'interface, non audité)
     */
    private void sendArtifact(Context ctx, Artifact artifact, String downloadName) {
        Actor actor = RequestContext.actor(ctx);
        AnalysisJob job = job(ctx);
        String id = job.id();
        byte[] content = repository.readArtifact(id, artifact)
                .orElseThrow(() -> new ApiServer.NotFound("Fichier " + artifact.fileName() + " indisponible pour " + id));
        ctx.contentType(artifact.contentType());
        if (downloadName != null) {
            attachment(ctx, downloadName.formatted(fileStem(job)));
            audit.record(actor, "ARTIFACT_DOWNLOADED", id, artifact.fileName());
        }
        ctx.result(content);
    }

    /** Archive ZIP de tous les fichiers disponibles de l'analyse (CBOM, rapport, SARIF, journal). */
    private void sendBundle(Context ctx) throws IOException {
        Actor actor = RequestContext.actor(ctx);
        AnalysisJob job = job(ctx);
        String stem = fileStem(job);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int entries = 0;
        try (ZipOutputStream zip = new ZipOutputStream(buffer, StandardCharsets.UTF_8)) {
            for (Map.Entry<Artifact, String> entry : BUNDLE_NAMES.entrySet()) {
                Optional<byte[]> content = repository.readArtifact(job.id(), entry.getKey());
                if (content.isPresent()) {
                    zip.putNextEntry(new ZipEntry(entry.getValue().formatted(stem)));
                    zip.write(content.get());
                    zip.closeEntry();
                    entries++;
                }
            }
        }
        if (entries == 0) {
            throw new ApiServer.NotFound("Aucun fichier disponible pour " + job.id());
        }
        attachment(ctx, "chiffrium-" + stem + ".zip");
        audit.record(actor, "ARTIFACT_DOWNLOADED", job.id(), "archive complète");
        ctx.contentType("application/zip").result(buffer.toByteArray());
    }

    /** Nom lisible et sûr : "bc-java-2026-09-22" (libellé ou dépôt, puis date de l'analyse). */
    static String fileStem(AnalysisJob job) {
        String name = job.label() != null ? job.label() : AnalysisService.shortName(job.request().target());
        String safe = UNSAFE_FILE_CHARS.matcher(name).replaceAll("-").replaceAll("-{2,}", "-")
                .replaceAll("^-|-$", "");
        if (safe.length() > MAX_STEM_LENGTH) {
            safe = safe.substring(0, MAX_STEM_LENGTH);
        }
        LocalDate date = LocalDate.ofInstant(job.finishedAt() != null ? job.finishedAt() : job.createdAt(),
                ZoneOffset.UTC);
        return (safe.isEmpty() ? "analyse" : safe) + "-" + date;
    }

    private static void attachment(Context ctx, String fileName) {
        ctx.header("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
    }

    private static String validId(Context ctx, String parameter) {
        String id = ctx.pathParam(parameter);
        if (!AnalysisIds.isValid(id)) {
            throw new ApiServer.NotFound("Analyse introuvable : " + id);
        }
        return id;
    }
}
