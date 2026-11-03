package com.chiffrium.application;

/**
 * Levée entre deux étapes quand l'utilisateur a demandé l'arrêt de l'analyse (thread interrompu).
 */
public final class AnalysisCancelledException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AnalysisCancelledException() {
        super("Analyse arrêtée à la demande de l'utilisateur.");
    }
}
