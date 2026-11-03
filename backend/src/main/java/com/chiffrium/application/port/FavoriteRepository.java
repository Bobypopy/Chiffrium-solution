package com.chiffrium.application.port;

import java.util.Set;

/**
 * Analyses marquées comme favorites, par utilisateur.
 */
public interface FavoriteRepository {

    void add(String userId, String analysisId);

    void remove(String userId, String analysisId);

    Set<String> analysisIds(String userId);

    /** Nettoyage quand une analyse est supprimée ou purgée. */
    void removeAnalysis(String analysisId);
}
