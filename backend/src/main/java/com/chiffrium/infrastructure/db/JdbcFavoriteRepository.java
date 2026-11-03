package com.chiffrium.infrastructure.db;

import com.chiffrium.application.port.FavoriteRepository;

import java.time.Clock;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Favoris en base.
 */
public final class JdbcFavoriteRepository implements FavoriteRepository {

    private final Jdbc jdbc;
    private final Clock clock;

    public JdbcFavoriteRepository(Database database, Clock clock) {
        this.jdbc = new Jdbc(database);
        this.clock = clock;
    }

    @Override
    public void add(String userId, String analysisId) {
        jdbc.upsert("favorites", "user_id, analysis_id", "user_id, analysis_id, created_at", userId, analysisId,
                clock.instant());
    }

    @Override
    public void remove(String userId, String analysisId) {
        jdbc.update("DELETE FROM favorites WHERE user_id = ? AND analysis_id = ?", userId, analysisId);
    }

    @Override
    public Set<String> analysisIds(String userId) {
        return new LinkedHashSet<>(jdbc.query("SELECT analysis_id FROM favorites WHERE user_id = ? ORDER BY created_at DESC",
                rs -> rs.getString(1), userId));
    }

    @Override
    public void removeAnalysis(String analysisId) {
        jdbc.update("DELETE FROM favorites WHERE analysis_id = ?", analysisId);
    }
}
