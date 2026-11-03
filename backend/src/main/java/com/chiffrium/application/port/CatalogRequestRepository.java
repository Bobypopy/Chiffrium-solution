package com.chiffrium.application.port;

import com.chiffrium.domain.security.CatalogRequest;

import java.util.List;
import java.util.Optional;

/**
 * Persistance des demandes de modification du catalogue.
 */
public interface CatalogRequestRepository {

    void save(CatalogRequest request);

    Optional<CatalogRequest> find(String id);

    /** Demandes de la plus récente à la plus ancienne. */
    List<CatalogRequest> findAll();
}
