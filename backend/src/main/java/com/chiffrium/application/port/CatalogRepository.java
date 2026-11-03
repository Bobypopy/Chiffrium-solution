package com.chiffrium.application.port;

import com.chiffrium.domain.policy.AlgorithmCatalog;

/**
 * Persistance du catalogue d'algorithmes (politique cryptographique).
 */
public interface CatalogRepository {

    AlgorithmCatalog load();

    void save(AlgorithmCatalog catalog);

    /** Catalogue livré avec l'application (référence des OID officiels). */
    AlgorithmCatalog defaults();
}
