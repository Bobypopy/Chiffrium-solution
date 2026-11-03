package com.chiffrium.application;

import com.chiffrium.domain.model.StepMetric;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Exécute les étapes d'une analyse en mesurant leur durée et en journalisant leur résultat.
 * Une étape "optionnelle" qui échoue n'interrompt pas l'analyse : l'erreur devient un avertissement.
 */
final class StepRecorder {

    private static final Logger LOG = LoggerFactory.getLogger(StepRecorder.class);

    private final Clock clock;
    private final Consumer<String> onStepStart;
    private final Consumer<StepMetric> onStepEnd;
    private final List<StepMetric> metrics = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();

    StepRecorder(Clock clock, Consumer<String> onStepStart, Consumer<StepMetric> onStepEnd) {
        this.clock = clock;
        this.onStepStart = onStepStart;
        this.onStepEnd = onStepEnd;
    }

    /** Étape obligatoire : toute exception est propagée et fait échouer l'analyse. */
    <T> T required(String step, Supplier<T> action, Function<T, String> describe) {
        checkCancelled();
        onStepStart.accept(step);
        long start = clock.millis();
        try {
            T result = action.get();
            record(step, StepMetric.Status.SUCCEEDED, start, describe.apply(result));
            return result;
        } catch (RuntimeException e) {
            record(step, StepMetric.Status.FAILED, start, e.getMessage());
            throw e;
        }
    }

    /** Étape optionnelle : en cas d'erreur, la valeur de repli est renvoyée et un avertissement est ajouté. */
    <T> T optional(String step, Supplier<T> action, Function<T, String> describe, T fallback) {
        checkCancelled();
        onStepStart.accept(step);
        long start = clock.millis();
        try {
            T result = action.get();
            record(step, StepMetric.Status.SUCCEEDED, start, describe.apply(result));
            return result;
        } catch (RuntimeException e) {
            if (e instanceof AnalysisCancelledException || Thread.currentThread().isInterrupted()) {
                // Arrêt demandé pendant l'étape (processus externe tué) : ne pas continuer avec l'étape suivante.
                record(step, StepMetric.Status.FAILED, start, "interrompue");
                throw e instanceof AnalysisCancelledException ? e : new AnalysisCancelledException();
            }
            LOG.warn("Étape '{}' en échec, l'analyse continue", step, e);
            warnings.add("Étape \"" + step + "\" en échec : " + e.getMessage());
            record(step, StepMetric.Status.FAILED, start, e.getMessage());
            return fallback;
        }
    }

    /** Point d'arrêt coopératif : l'interruption du thread signale une demande d'arrêt. */
    static void checkCancelled() {
        if (Thread.currentThread().isInterrupted()) {
            throw new AnalysisCancelledException();
        }
    }

    void skipped(String step, String reason) {
        StepMetric metric = new StepMetric(step, StepMetric.Status.SKIPPED, 0, reason);
        metrics.add(metric);
        onStepEnd.accept(metric);
        LOG.info("Étape '{}' ignorée : {}", step, reason);
    }

    void warn(List<String> messages) {
        warnings.addAll(messages);
    }

    List<StepMetric> metrics() {
        return List.copyOf(metrics);
    }

    List<String> warnings() {
        return List.copyOf(warnings);
    }

    private void record(String step, StepMetric.Status status, long start, String message) {
        long duration = clock.millis() - start;
        StepMetric metric = new StepMetric(step, status, duration, message);
        metrics.add(metric);
        onStepEnd.accept(metric);
        LOG.info("Étape '{}' {} en {} ms{}", step, status.id(), duration, message == null ? "" : " : " + message);
    }
}
