package com.chiffrium.application.port;

import com.chiffrium.domain.model.AnalysisRequest;

import java.nio.file.Path;

/**
 * Récupère le code à analyser (clonage Git ou dossier local autorisé).
 */
public interface SourceFetcher {

    /**
     * @param request   paramètres de l'analyse
     * @param workspace dossier de travail propre à l'analyse (vide)
     * @return la racine du code récupéré et ses métadonnées
     * @throws AnalysisException si la cible est invalide, interdite ou inaccessible
     */
    FetchedSource fetch(AnalysisRequest request, Path workspace);

    /**
     * @param root   racine du code à analyser
     * @param kind   "git" ou "local"
     * @param branch branche récupérée (Git)
     * @param commit commit récupéré (Git)
     */
    record FetchedSource(Path root, String kind, String branch, String commit) {
    }
}
