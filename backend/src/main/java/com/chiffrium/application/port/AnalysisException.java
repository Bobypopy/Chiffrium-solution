package com.chiffrium.application.port;

/**
 * Erreur métier d'une analyse, avec un message destiné à l'utilisateur.
 */
public class AnalysisException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AnalysisException(String message) {
        super(message);
    }

    public AnalysisException(String message, Throwable cause) {
        super(message, cause);
    }
}
