package com.chiffrium.domain.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * État d'une analyse (fichier analysis.json). Objet immuable : chaque transition produit une nouvelle instance.
 *
 * @param id          identifiant (UUID)
 * @param request     paramètres demandés
 * @param requestedBy utilisateur ayant demandé l'analyse (traçabilité, droits de suppression)
 * @param groupId     groupe auquel l'analyse est rattachée (visible de ses membres), null si privée
 * @param label       libellé libre donné par l'utilisateur (ex. "avant migration TLS"), null si aucun
 * @param status      état courant
 * @param createdAt   date de soumission
 * @param startedAt   date de démarrage
 * @param finishedAt  date de fin
 * @param currentStep étape en cours
 * @param steps       étapes terminées
 * @param summary     indicateurs (renseignés en fin d'analyse réussie)
 * @param error       message d'erreur en cas d'échec
 */
public record AnalysisJob(
        String id,
        AnalysisRequest request,
        String requestedBy,
        String groupId,
        String label,
        AnalysisStatus status,
        Instant createdAt,
        Instant startedAt,
        Instant finishedAt,
        String currentStep,
        List<StepMetric> steps,
        Summary summary,
        String error) {

    public static final int MAX_LABEL_LENGTH = 100;

    public AnalysisJob {
        steps = steps == null ? List.of() : List.copyOf(steps);
    }

    public static AnalysisJob queued(String id, AnalysisRequest request, String requestedBy, Instant now) {
        return queued(id, request, requestedBy, null, now);
    }

    public static AnalysisJob queued(String id, AnalysisRequest request, String requestedBy, String groupId,
                                     Instant now) {
        return new AnalysisJob(id, request, requestedBy, groupId, null, AnalysisStatus.QUEUED, now, null, null, null,
                List.of(), null, null);
    }

    public AnalysisJob started(Instant now) {
        return new AnalysisJob(id, request, requestedBy, groupId, label, AnalysisStatus.RUNNING, createdAt, now, null,
                null, steps, null, null);
    }

    public AnalysisJob enteringStep(String step) {
        return new AnalysisJob(id, request, requestedBy, groupId, label, status, createdAt, startedAt, finishedAt, step,
                steps, summary, error);
    }

    public AnalysisJob withStep(StepMetric metric) {
        List<StepMetric> updated = new ArrayList<>(steps);
        updated.add(metric);
        return new AnalysisJob(id, request, requestedBy, groupId, label, status, createdAt, startedAt, finishedAt, null,
                updated, summary, error);
    }

    public AnalysisJob succeeded(Summary finalSummary, Instant now) {
        return new AnalysisJob(id, request, requestedBy, groupId, label, AnalysisStatus.SUCCEEDED, createdAt, startedAt,
                now, null, steps, finalSummary, null);
    }

    public AnalysisJob failed(String message, Instant now) {
        return new AnalysisJob(id, request, requestedBy, groupId, label, AnalysisStatus.FAILED, createdAt, startedAt,
                now, null, steps, summary, message);
    }

    /** Remise en file après un arrêt du service (mise à jour, redémarrage) : l'analyse reprendra depuis le début. */
    public AnalysisJob requeued() {
        return new AnalysisJob(id, request, requestedBy, groupId, label, AnalysisStatus.QUEUED, createdAt, null, null,
                null, List.of(), null, null);
    }

    /** Arrêt à la demande d'un utilisateur ; les étapes déjà terminées restent consultables. */
    public AnalysisJob cancelled(String message, Instant now) {
        return new AnalysisJob(id, request, requestedBy, groupId, label, AnalysisStatus.CANCELLED, createdAt, startedAt,
                now, null, steps, summary, message);
    }

    /** Partage avec un groupe (null : analyse privée). */
    public AnalysisJob withGroup(String newGroupId) {
        return new AnalysisJob(id, request, requestedBy, newGroupId, label, status, createdAt, startedAt, finishedAt,
                currentStep, steps, summary, error);
    }

    public AnalysisJob withLabel(String newLabel) {
        return new AnalysisJob(id, request, requestedBy, groupId, newLabel, status, createdAt, startedAt, finishedAt,
                currentStep, steps, summary, error);
    }
}
