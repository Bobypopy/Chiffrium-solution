package com.chiffrium.application.port;

import com.chiffrium.domain.model.Library;

import java.util.List;

/**
 * Lit les dépendances (bibliothèques) contenues dans les SBOM produits.
 */
public interface LibraryReader {

    List<Library> read(SbomGenerator.SbomResult sbom);
}
