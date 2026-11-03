package com.chiffrium.application;

import java.nio.file.Path;
import java.time.Duration;

/**
 * Réglages du pipeline issus de la configuration.
 *
 * @param workspaceRoot     dossier racine des espaces de travail temporaires (clones)
 * @param keepWorkspace     conserver le clone après l'analyse (débogage)
 * @param defaultCdxgenTimeout durée par défaut d'une exécution de cdxgen
 * @param minCdxgenTimeout  borne basse acceptée pour une demande utilisateur
 * @param maxCdxgenTimeout  borne haute acceptée pour une demande utilisateur
 * @param toolVersion       version de l'analyseur
 */
public record PipelineSettings(
        Path workspaceRoot,
        boolean keepWorkspace,
        Duration defaultCdxgenTimeout,
        Duration minCdxgenTimeout,
        Duration maxCdxgenTimeout,
        String toolVersion) {

    /** Borne la durée demandée par l'utilisateur dans l'intervalle autorisé. */
    public Duration cdxgenTimeout(Integer requestedSeconds) {
        if (requestedSeconds == null) {
            return defaultCdxgenTimeout;
        }
        Duration requested = Duration.ofSeconds(requestedSeconds);
        if (requested.compareTo(minCdxgenTimeout) < 0) {
            return minCdxgenTimeout;
        }
        return requested.compareTo(maxCdxgenTimeout) > 0 ? maxCdxgenTimeout : requested;
    }
}
