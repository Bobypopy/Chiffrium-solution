package com.chiffrium.infrastructure.db;

import com.chiffrium.application.port.CatalogRequestRepository;
import com.chiffrium.domain.policy.AlgorithmDefinition;
import com.chiffrium.domain.security.CatalogRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

/**
 * Demandes de modification du catalogue en base (l'entrée proposée est stockée en JSON).
 */
public final class JdbcCatalogRequestRepository implements CatalogRequestRepository {

    private static final String COLUMNS = "id, kind, algorithm_id, proposal, justification, requested_by, group_id, "
            + "status, reviewed_by, review_comment, created_at, reviewed_at";

    private final Jdbc jdbc;
    private final ObjectMapper mapper;

    public JdbcCatalogRequestRepository(Database database, ObjectMapper mapper) {
        this.jdbc = new Jdbc(database);
        this.mapper = mapper;
    }

    @Override
    public void save(CatalogRequest r) {
        jdbc.upsert("catalog_requests", "id", COLUMNS, r.id(), r.kind().name(), r.algorithmId(), toJson(r.proposal()),
                r.justification(), r.requestedBy(), r.groupId(), r.status().name(), r.reviewedBy(), r.reviewComment(),
                r.createdAt(), r.reviewedAt());
    }

    @Override
    public Optional<CatalogRequest> find(String id) {
        return jdbc.queryOne("SELECT " + COLUMNS + " FROM catalog_requests WHERE id = ?", this::map, id);
    }

    @Override
    public List<CatalogRequest> findAll() {
        return jdbc.query("SELECT " + COLUMNS + " FROM catalog_requests ORDER BY created_at DESC", this::map);
    }

    private CatalogRequest map(ResultSet rs) throws SQLException {
        return new CatalogRequest(rs.getString("id"), CatalogRequest.Kind.valueOf(rs.getString("kind")),
                rs.getString("algorithm_id"), fromJson(rs.getString("proposal")), rs.getString("justification"),
                rs.getString("requested_by"), rs.getString("group_id"),
                CatalogRequest.Status.valueOf(rs.getString("status")), rs.getString("reviewed_by"),
                rs.getString("review_comment"), Jdbc.instant(rs, "created_at"), Jdbc.instant(rs, "reviewed_at"));
    }

    private String toJson(AlgorithmDefinition definition) {
        try {
            return definition == null ? null : mapper.writeValueAsString(definition);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Proposition non sérialisable", e);
        }
    }

    private AlgorithmDefinition fromJson(String json) {
        try {
            return json == null ? null : mapper.readValue(json, AlgorithmDefinition.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Proposition illisible", e);
        }
    }
}
