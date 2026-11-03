package com.chiffrium.domain.model;

import java.util.List;
import java.util.Set;

/**
 * Description de la source analysée.
 *
 * @param target    cible demandée (URL Git ou chemin)
 * @param kind      git ou local
 * @param branch    branche analysée (Git)
 * @param commit    commit analysé (Git)
 * @param languages langages détectés sur l'ensemble du projet
 * @param modules   sous-projets détectés
 */
public record SourceInfo(
        String target,
        String kind,
        String branch,
        String commit,
        Set<Language> languages,
        List<ProjectModule> modules) {

    public SourceInfo {
        languages = languages == null ? Set.of() : Set.copyOf(languages);
        modules = modules == null ? List.of() : List.copyOf(modules);
    }
}
