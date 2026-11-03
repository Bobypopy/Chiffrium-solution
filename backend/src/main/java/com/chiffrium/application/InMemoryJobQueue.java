package com.chiffrium.application;

import com.chiffrium.application.port.JobQueue;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * File locale (une seule instance du service) : les analyses interrompues par un arrêt sont traitées au
 * démarrage par {@link AnalysisService#recoverInterrupted()}.
 */
public final class InMemoryJobQueue implements JobQueue {

    private final LinkedBlockingQueue<String> queue = new LinkedBlockingQueue<>();

    @Override
    public void enqueue(String analysisId) {
        queue.add(analysisId);
    }

    @Override
    public Optional<String> take(Duration wait) throws InterruptedException {
        return Optional.ofNullable(queue.poll(wait.toMillis(), TimeUnit.MILLISECONDS));
    }

    @Override
    public int pending() {
        return queue.size();
    }

    @Override
    public void heartbeat(String analysisId) {
        // Une seule instance : rien à signaler.
    }

    @Override
    public List<String> abandoned(Duration staleAfter) {
        return List.of();
    }
}
