package com.chiffrium.application;

import com.chiffrium.application.port.AnalysisException;
import com.chiffrium.application.port.AnalysisRepository;
import com.chiffrium.application.port.FavoriteRepository;
import com.chiffrium.application.port.JobQueue;
import com.chiffrium.application.security.AccessDeniedException;
import com.chiffrium.application.security.Actor;
import com.chiffrium.application.security.AuditService;
import com.chiffrium.application.security.NotificationService;
import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.model.AnalysisReport;
import com.chiffrium.domain.model.AnalysisRequest;
import com.chiffrium.domain.model.AnalysisStatus;
import com.chiffrium.domain.model.Severity;
import com.chiffrium.domain.policy.ReportComparator;
import com.chiffrium.domain.security.Permission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

/**
 * Cas d'usage autour des analyses : soumission (file bornée), exécution par des travailleurs qui puisent dans la
 * {@link JobQueue} (locale ou partagée entre répliques), suivi, partage, favoris, comparaison, suppression.
 * Le nombre d'analyses simultanées est limité car cdxgen est gourmand en CPU et mémoire.
 */
public final class AnalysisService implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(AnalysisService.class);
    /** Clé MDC utilisée par la configuration de logs pour écrire un journal par analyse. */
    public static final String MDC_ANALYSIS_ID = "analysisId";
    /**
     * Délai laissé aux travailleurs pour enregistrer l'état des analyses interrompues à l'arrêt du service
     * (l'application de bureau arrête le moteur au bout de 15 s).
     */
    private static final long SHUTDOWN_GRACE_SECONDS = 10;
    /** Attente maximale d'un travailleur sur la file avant de revérifier l'arrêt du service. */
    static final Duration POLL_WAIT = Duration.ofSeconds(2);
    /** Une analyse sans signe de vie depuis ce délai appartient à une réplique arrêtée. */
    static final Duration ABANDONED_AFTER = Duration.ofMinutes(10);
    private static final String INTERRUPTED_MESSAGE = "Analyse interrompue par un arrêt inattendu du service : "
            + "relancez-la (menu \"Plus\").";
    private static final String ABANDONED_MESSAGE = "Analyse interrompue : le serveur qui l'exécutait s'est arrêté.";

    private final AnalysisPipeline pipeline;
    private final AnalysisRepository repository;
    private final AuditService audit;
    private final AnalysisAccess access;
    private final FavoriteRepository favorites;
    private final NotificationService notifier;
    private final JobQueue queue;
    private final Clock clock;
    private final Supplier<String> idGenerator;
    private final BooleanSupplier keepRawOutputs;
    private final int maxQueued;
    private final ExecutorService workers;
    private final Map<String, AnalysisJob> activeJobs = new ConcurrentHashMap<>();
    /** Thread qui exécute chaque analyse de cette instance (arrêt par interruption). Verrou : la map elle-même. */
    private final Map<String, Thread> runningThreads = new java.util.HashMap<>();
    /** Arrêts demandés : identifiant d'analyse -> auteur de la demande. */
    private final Map<String, String> cancelRequests = new ConcurrentHashMap<>();
    /** Étape affichée entre la demande d'arrêt et l'arrêt effectif. */
    public static final String STOPPING_STEP = "arrêt en cours";
    private volatile boolean running = true;
    /** Arrêt du service en cours : les analyses interrompues sont remises en file au lieu d'échouer. */
    private volatile boolean shuttingDown;

    /** Activité de cette instance (arrêt ou mise à jour de l'application sans perdre d'analyse). */
    public record Activity(int running, int queued) {
    }

    /**
     * Dépendances d'exécution d'{@link AnalysisService}.
     *
     * @param keepRawOutputs lu à la fin de chaque analyse : conserver (chiffrées) les sorties brutes de cdxgen
     */
    public record Settings(Clock clock, Supplier<String> idGenerator, BooleanSupplier keepRawOutputs,
                           int maxConcurrent, int maxQueued) {
    }

    public AnalysisService(AnalysisPipeline pipeline, AnalysisRepository repository, AuditService audit,
                           AnalysisAccess access, FavoriteRepository favorites, NotificationService notifier,
                           JobQueue queue, Settings settings) {
        this.pipeline = pipeline;
        this.repository = repository;
        this.audit = audit;
        this.access = access;
        this.favorites = favorites;
        this.notifier = notifier;
        this.queue = queue;
        this.clock = settings.clock();
        this.idGenerator = settings.idGenerator();
        this.keepRawOutputs = settings.keepRawOutputs();
        this.maxQueued = settings.maxQueued();
        AtomicInteger threadCounter = new AtomicInteger();
        this.workers = Executors.newFixedThreadPool(settings.maxConcurrent(), runnable -> {
            Thread thread = new Thread(runnable, "analysis-worker-" + threadCounter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
        for (int i = 0; i < settings.maxConcurrent(); i++) {
            workers.execute(this::workLoop);
        }
    }

    /**
     * Soumet une ou plusieurs analyses (ex. liste d'URL Git).
     *
     * @param groupId groupe auquel rattacher les analyses (null : analyses privées)
     * @throws QueueFullException    si la file d'attente ne peut pas accueillir toutes les demandes
     * @throws AccessDeniedException si l'acteur n'appartient pas au groupe
     */
    public List<AnalysisJob> submit(Actor actor, List<AnalysisRequest> requests, String groupId) {
        actor.require(Permission.RUN_ANALYSIS);
        if (!access.scope(actor).canUseGroup(groupId)) {
            throw new AccessDeniedException("Vous n'appartenez pas à ce groupe.");
        }
        int freeSlots = maxQueued - queue.pending();
        if (requests.size() > freeSlots) {
            throw new QueueFullException("File d'attente pleine : " + Math.max(0, freeSlots) + " place(s) disponible(s) "
                    + "pour " + requests.size() + " demande(s). Réessayer plus tard.");
        }
        List<AnalysisJob> jobs = new ArrayList<>();
        for (AnalysisRequest request : requests) {
            AnalysisJob job = AnalysisJob.queued(idGenerator.get(), request, actor.username(), groupId,
                    clock.instant());
            repository.save(job);
            queue.enqueue(job.id());
            jobs.add(job);
            audit.record(actor, "ANALYSIS_SUBMITTED", job.id(), request.target());
            LOG.info("Analyse {} mise en file pour {}", job.id(), request.target());
        }
        return jobs;
    }

    /** Relance une analyse avec les mêmes paramètres et le même groupe (si l'acteur en est membre). */
    public AnalysisJob rerun(Actor actor, String id) {
        AnalysisJob original = visible(actor, id);
        String groupId = access.scope(actor).canUseGroup(original.groupId()) ? original.groupId() : null;
        return submit(actor, List.of(original.request()), groupId).get(0);
    }

    /**
     * Arrête une analyse en attente (immédiatement) ou en cours (processus externes tués, espace de travail
     * nettoyé ; les étapes terminées restent consultables). Mêmes droits que la suppression.
     */
    public AnalysisJob cancel(Actor actor, String id) {
        AnalysisJob job = visible(actor, id);
        if (job.status().isTerminal()) {
            throw new IllegalArgumentException("Cette analyse est déjà terminée.");
        }
        if (!access.scope(actor).canDelete(job)) {
            throw new AccessDeniedException("Seuls le demandeur, un responsable du groupe ou un administrateur "
                    + "peuvent arrêter cette analyse.");
        }
        cancelRequests.put(id, actor.username());
        audit.record(actor, "ANALYSIS_CANCELLED", id, job.status().id());
        Thread thread;
        synchronized (runningThreads) {
            thread = runningThreads.get(id);
            if (thread != null) {
                thread.interrupt();
            }
        }
        if (thread != null) {
            LOG.info("Arrêt demandé par {} pour l'analyse {} en cours", actor.username(), id);
            // L'état est publié : toutes les pages ouvertes voient "arrêt en cours" sans attendre la fin de
            // l'étape (un clonage Git ne s'interrompt qu'entre deux phases, jusqu'à une minute).
            AnalysisJob stopping = activeJobs.getOrDefault(id, job).enteringStep(STOPPING_STEP);
            activeJobs.put(id, stopping);
            return stopping;
        }
        // En attente, ou en cours sur une autre réplique (qui verra le statut à sa prochaine étape).
        AnalysisJob cancelled = job.cancelled(cancelMessage(actor.username()), clock.instant());
        repository.save(cancelled);
        cancelRequests.remove(id);
        return cancelled;
    }

    public Activity activity() {
        int queued = (int) repository.findAll().stream().filter(j -> j.status() == AnalysisStatus.QUEUED).count();
        return new Activity(activeIds().size(), queued);
    }

    /** Analyses en cours d'exécution sur cette instance (leurs copies de travail ne doivent pas être supprimées). */
    public Set<String> activeIds() {
        Set<String> ids = new java.util.HashSet<>(activeJobs.keySet());
        synchronized (runningThreads) {
            ids.addAll(runningThreads.keySet());
        }
        return ids;
    }

    private static String cancelMessage(String username) {
        return "Analyse arrêtée par " + username + ".";
    }

    /** Point d'arrêt entre les étapes : demande locale ou statut "arrêtée" écrit par une autre réplique. */
    private void abortIfCancelled(String id) {
        boolean requested = cancelRequests.containsKey(id)
                || repository.find(id).map(j -> j.status() == AnalysisStatus.CANCELLED).orElse(false);
        if (requested) {
            Thread.currentThread().interrupt();
            throw new AnalysisCancelledException();
        }
    }

    /** Analyse visible par l'acteur (vide si inconnue ou non visible : on ne révèle pas son existence). */
    public Optional<AnalysisJob> find(Actor actor, String id) {
        AnalysisJob active = activeJobs.get(id);
        Optional<AnalysisJob> job = active != null ? Optional.of(active) : repository.find(id);
        return job.filter(access.scope(actor)::canView);
    }

    /** Analyses visibles par l'acteur, des plus récentes aux plus anciennes. */
    public List<AnalysisJob> list(Actor actor) {
        AnalysisAccess.Scope scope = access.scope(actor);
        return repository.findAll().stream()
                .map(job -> activeJobs.getOrDefault(job.id(), job))
                .filter(scope::canView)
                .toList();
    }

    /**
     * Partage une analyse avec un groupe de l'acteur, ou la rend privée ({@code groupId} null). Réservé au
     * demandeur, aux responsables du groupe actuel et aux administrateurs.
     */
    public AnalysisJob share(Actor actor, String id, String groupId) {
        AnalysisJob job = visible(actor, id);
        AnalysisAccess.Scope scope = access.scope(actor);
        if (!scope.canDelete(job)) {
            throw new AccessDeniedException("Seuls le demandeur, un responsable du groupe ou un administrateur "
                    + "peuvent changer la visibilité de cette analyse.");
        }
        if (!scope.canUseGroup(groupId)) {
            throw new AccessDeniedException("Vous n'appartenez pas à ce groupe.");
        }
        AnalysisJob updated = job.withGroup(groupId);
        repository.save(updated);
        activeJobs.computeIfPresent(id, (k, v) -> v.withGroup(groupId));
        audit.record(actor, "ANALYSIS_SHARED", id, groupId == null ? "privée" : "groupe " + groupId);
        return updated;
    }

    /** Donne un libellé à une analyse (ex. "avant migration"). */
    public AnalysisJob label(Actor actor, String id, String label) {
        AnalysisJob job = visible(actor, id);
        if (!access.scope(actor).canDelete(job)) {
            throw new AccessDeniedException("Seuls le demandeur, un responsable du groupe ou un administrateur "
                    + "peuvent renommer cette analyse.");
        }
        String clean = label == null || label.isBlank() ? null : label.strip();
        if (clean != null && clean.length() > AnalysisJob.MAX_LABEL_LENGTH) {
            throw new IllegalArgumentException("Libellé trop long (" + AnalysisJob.MAX_LABEL_LENGTH + " caractères max).");
        }
        AnalysisJob updated = job.withLabel(clean);
        repository.save(updated);
        activeJobs.computeIfPresent(id, (k, v) -> v.withLabel(clean));
        return updated;
    }

    /**
     * Dérive entre deux analyses visibles par l'acteur.
     *
     * @throws IllegalArgumentException si l'une des analyses est introuvable ou sans rapport
     */
    public ReportComparator.Comparison compare(Actor actor, String baseId, String targetId) {
        AnalysisReport base = visibleReport(actor, baseId);
        AnalysisReport target = visibleReport(actor, targetId);
        return new ReportComparator().compare(base, target);
    }

    /** Ajoute ou retire une analyse des favoris de l'acteur. */
    public void setFavorite(Actor actor, String id, boolean favorite) {
        visible(actor, id);
        if (favorite) {
            favorites.add(actor.userId(), id);
        } else {
            favorites.remove(actor.userId(), id);
        }
    }

    public Set<String> favoriteIds(Actor actor) {
        return actor.userId() == null ? Set.of() : favorites.analysisIds(actor.userId());
    }

    /**
     * @return false si l'analyse n'existe pas
     * @throws AnalysisException     si l'analyse est en attente ou en cours
     * @throws AccessDeniedException si l'acteur n'est ni le demandeur, ni responsable du groupe, ni administrateur
     */
    public boolean delete(Actor actor, String id) {
        AnalysisAccess.Scope scope = access.scope(actor);
        Optional<AnalysisJob> job = repository.find(id).filter(scope::canView);
        if (job.isEmpty()) {
            return false;
        }
        if (activeJobs.containsKey(id) || !job.get().status().isTerminal()) {
            throw new AnalysisException("Impossible de supprimer une analyse en attente ou en cours.");
        }
        if (!scope.canDelete(job.get())) {
            throw new AccessDeniedException("Seuls le demandeur, un responsable du groupe ou un administrateur "
                    + "peuvent supprimer cette analyse.");
        }
        repository.delete(id);
        favorites.removeAnalysis(id);
        audit.record(actor, "ANALYSIS_DELETED", id, job.get().request().target());
        return true;
    }

    /** Suppression par la politique de rétention (pas de contrôle de propriétaire). */
    void purge(String id, String reason) {
        if (activeJobs.containsKey(id)) {
            return;
        }
        repository.delete(id);
        favorites.removeAnalysis(id);
        audit.record(Actor.SYSTEM, "ANALYSIS_PURGED", id, reason);
    }

    /**
     * Au démarrage d'un service local, les analyses "en attente" (y compris celles interrompues par un arrêt
     * propre) sont remises en file ; celles restées "en cours" après un arrêt brutal sont marquées en échec (les
     * relancer automatiquement risquerait une boucle si l'analyse elle-même a fait tomber le service).
     */
    public void recoverInterrupted() {
        repository.findAll().stream()
                .filter(job -> !job.status().isTerminal())
                .forEach(job -> {
                    if (job.startedAt() == null) {
                        queue.enqueue(job.id());
                    } else {
                        LOG.warn("Analyse {} interrompue lors d'un arrêt précédent", job.id());
                        repository.save(job.failed(INTERRUPTED_MESSAGE, clock.instant()));
                    }
                });
    }

    /** Serveur multi-répliques : analyses d'une réplique arrêtée marquées en échec (tâche périodique). */
    public int failAbandoned() {
        int count = 0;
        for (String id : queue.abandoned(ABANDONED_AFTER)) {
            Optional<AnalysisJob> job = repository.find(id).filter(j -> !j.status().isTerminal());
            if (job.isPresent()) {
                repository.save(job.get().failed(ABANDONED_MESSAGE, clock.instant()));
                audit.record(Actor.SYSTEM, "ANALYSIS_FAILED", id, ABANDONED_MESSAGE);
                count++;
            }
        }
        return count;
    }

    private void workLoop() {
        while (running) {
            try {
                queue.take(POLL_WAIT).ifPresent(this::execute);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (RuntimeException | StackOverflowError e) {
                LOG.error("Erreur du travailleur d'analyse", e);
            }
        }
    }

    private void execute(String id) {
        Optional<AnalysisJob> queued = repository.find(id).filter(job -> !job.status().isTerminal());
        if (queued.isEmpty()) {
            return;
        }
        MDC.put(MDC_ANALYSIS_ID, id);
        synchronized (runningThreads) {
            runningThreads.put(id, Thread.currentThread());
        }
        AnalysisJob outcome;
        AnalysisReport report = null;
        try {
            AnalysisJob job = update(queued.get().started(clock.instant()));
            LOG.info("Démarrage de l'analyse de {}", job.request().target());
            report = pipeline.run(job,
                    step -> {
                        abortIfCancelled(id);
                        update(activeJobs.get(id).enteringStep(step));
                    },
                    metric -> update(activeJobs.get(id).withStep(metric)));
            outcome = activeJobs.get(id).succeeded(report.summary(), clock.instant());
            LOG.info("Analyse terminée : {} actif(s), score {}", report.summary().totalAssets(),
                    report.summary().score());
            audit.record(Actor.SYSTEM, "ANALYSIS_SUCCEEDED", id,
                    report.summary().totalAssets() + " actif(s), score " + report.summary().score());
        } catch (RuntimeException e) {
            AnalysisJob current = activeJobs.getOrDefault(id, queued.get());
            String by = cancelRequests.get(id);
            if (shuttingDown && by == null) {
                // Arrêt du service (mise à jour, fermeture de l'application) : reprise au prochain démarrage.
                LOG.info("Analyse interrompue par l'arrêt du service : remise en file");
                outcome = current.requeued();
            } else if (by != null || e instanceof AnalysisCancelledException) {
                LOG.info("Analyse arrêtée");
                outcome = current.cancelled(by != null ? cancelMessage(by)
                        : repository.find(id).map(AnalysisJob::error).orElse(e.getMessage()), clock.instant());
            } else {
                LOG.error("Analyse en échec", e);
                String message = e instanceof AnalysisException ? e.getMessage() : "Erreur interne : " + e.getMessage();
                outcome = current.failed(message, clock.instant());
                audit.record(Actor.SYSTEM, "ANALYSIS_FAILED", id, message);
            }
        } catch (StackOverflowError e) {
            // Un débordement de pile (expression régulière sur un fichier pathologique) ne doit ni tuer le
            // travailleur ni laisser l'analyse "en cours" indéfiniment.
            LOG.error("Analyse en échec", e);
            String message = "Erreur interne : fichier trop complexe à analyser";
            AnalysisJob current = activeJobs.getOrDefault(id, queued.get());
            outcome = current.failed(message, clock.instant());
            audit.record(Actor.SYSTEM, "ANALYSIS_FAILED", id, message);
        } finally {
            synchronized (runningThreads) {
                runningThreads.remove(id);
                // Une interruption destinée à cette analyse ne doit pas arrêter le travailleur.
                Thread.interrupted();
            }
            MDC.remove(MDC_ANALYSIS_ID);
        }
        if (outcome.status() == AnalysisStatus.QUEUED) {
            // Pas de scellement : l'analyse reprendra dans le même dossier (journal complété en clair).
            repository.save(outcome);
            activeJobs.remove(id);
            return;
        }
        // Les artefacts sont scellés (chiffrés, publiés) avant d'annoncer la fin : le rapport est alors lisible.
        sealQuietly(id);
        repository.save(outcome);
        activeJobs.remove(id);
        cancelRequests.remove(id);
        if (outcome.status() != AnalysisStatus.CANCELLED) {
            notifyOutcome(outcome, report);
        }
    }

    private void notifyOutcome(AnalysisJob job, AnalysisReport report) {
        String link = "#/report/" + job.id();
        String target = job.label() != null ? job.label() : shortName(job.request().target());
        if (report == null) {
            notifier.notifyUsername(job.requestedBy(), NotificationService.ANALYSIS_FINISHED, "Analyse en échec : "
                    + target, job.error(), link + "/steps");
            return;
        }
        long critical = report.findings().stream()
                .filter(f -> f.severity().compareTo(Severity.HIGH) >= 0 && !f.testCode()).count();
        String body = "Score " + report.summary().score() + "/100, " + report.summary().totalAssets() + " actif(s)"
                + (critical > 0 ? ", " + critical + " constat(s) graves" : "");
        notifier.notifyUsername(job.requestedBy(), NotificationService.ANALYSIS_FINISHED, "Analyse terminée : "
                + target, body, link);
        if (critical > 0) {
            notifier.alert("Constats graves dans " + target, body, link);
        }
    }

    /** Chiffre et publie les artefacts ; appelé une fois le journal de l'analyse refermé. */
    private void sealQuietly(String id) {
        try {
            repository.seal(id, keepRawOutputs.getAsBoolean());
        } catch (RuntimeException e) {
            LOG.error("Chiffrement des artefacts impossible pour l'analyse {}", id, e);
        }
    }

    private AnalysisJob update(AnalysisJob job) {
        activeJobs.put(job.id(), job);
        repository.save(job);
        queue.heartbeat(job.id());
        return job;
    }

    private AnalysisJob visible(Actor actor, String id) {
        return find(actor, id).orElseThrow(() -> new IllegalArgumentException("Analyse introuvable : " + id));
    }

    private AnalysisReport visibleReport(Actor actor, String id) {
        return find(actor, id).flatMap(job -> repository.readReport(id))
                .orElseThrow(() -> new IllegalArgumentException("Rapport indisponible pour l'analyse " + id));
    }

    @Override
    public void close() {
        running = false;
        shuttingDown = true;
        workers.shutdown();
        // Les analyses en cours sont interrompues tout de suite (processus externes tués) puis remises en file :
        // attendre leur fin bloquerait la fermeture de l'application ou un redéploiement pendant des minutes.
        synchronized (runningThreads) {
            runningThreads.values().forEach(Thread::interrupt);
        }
        try {
            if (!workers.awaitTermination(SHUTDOWN_GRACE_SECONDS, TimeUnit.SECONDS)) {
                workers.shutdownNow();
            }
        } catch (InterruptedException e) {
            workers.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /** Levée quand la file d'attente des analyses est saturée. */
    public static final class QueueFullException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public QueueFullException(String message) {
            super(message);
        }
    }

    /** Nom court d'une cible (dernier segment, sans ".git") pour les titres de notification. */
    public static String shortName(String target) {
        String trimmed = target.replaceAll("[/\\\\]+$", "");
        String last = trimmed.substring(Math.max(trimmed.lastIndexOf('/'), trimmed.lastIndexOf('\\')) + 1);
        return last.endsWith(".git") ? last.substring(0, last.length() - ".git".length()) : last;
    }
}
