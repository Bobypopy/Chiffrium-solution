package com.chiffrium;

import com.chiffrium.application.AnalysisService;
import com.chiffrium.application.security.Actor;
import com.chiffrium.application.security.AuditService;
import com.chiffrium.infrastructure.config.AppConfig;

/**
 * Accès des tests d'autres paquets au graphe d'objets réel de l'application (sans serveur HTTP).
 */
public final class MainAccess implements AutoCloseable {

    private static final String LOOPBACK = "127.0.0.1";
    private final Main.Application application;

    public MainAccess(AppConfig config) {
        this.application = new Main.Application(config);
    }

    /** Installe le premier administrateur et renvoie son identité. */
    public Actor admin(String password) {
        String setupToken = application.setupTokens.current().orElseThrow();
        String token = application.auth.setup(setupToken, "admin", password.toCharArray(), "Administrateur", LOOPBACK)
                .token();
        return application.auth.authenticate(token, LOOPBACK).actor();
    }

    public Actor system() {
        return Actor.SYSTEM;
    }

    public AnalysisService analyses() {
        return application.analysisService;
    }

    public AuditService audit() {
        return application.audit;
    }

    @Override
    public void close() {
        application.analysisService.close();
        application.database.close();
    }
}
